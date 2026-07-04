// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The `checkpoint_poseidon` component in the trace.
//!
//! Trace twins of the two killshots behind
//! `noid_recursive::checkpoint::verify_checkpoint_poseidon`:
//!
//! - [`verify_header_hash_killshot_padded_trace`] ←
//!   `noid_gkr::header_hash_killshot::verify_header_hash_killshot_padded`
//!   (+ its discharge), and
//! - [`verify_chain_accumulator_killshot_padded_trace`] ←
//!   `noid_gkr::chain_accumulator_killshot::verify_chain_accumulator_killshot_padded`
//!   (+ its discharge).
//!
//! Scope note (no header consensus belongs in the O(1) history proof): the
//! native `verify_checkpoint_poseidon` prepends `validate_shape` (the
//! `pow_fields == pow_header_fields(header)` recomputation from the header
//! STRUCT) and `validate_accumulator_boundary` (height / state_root
//! equalities). Those compare against header-layer objects that a fresh peer
//! validates natively — they belong to the [B] bindings / decider anchors,
//! not to the trace. The trace slot replays exactly the two killshot
//! verifiers and their discharges over the killshot field schedules
//! (`HeaderHashInputs`, `ChainAccumulatorBatchInputs`); the [B] slot pins
//! those same lanes to the receipt/accumulator publics at proof assembly.
//!
//! Each killshot runs on its OWN raw channel (native uses two fresh
//! `Poseidon2bChannel`s inside a `rayon::join`).

use noid_core::{Block128, TowerField};
use noid_gkr::chain_accumulator_killshot::{
    ChainAccumulatorBatchInputs, ChainAccumulatorProofKillShot, CHAIN_ACC_LINEAR_RELATION_TAG,
    CHAIN_ACC_PERMS_PER_ITEM, CHAIN_ACC_PIN_LANES,
};
use noid_gkr::header_hash_killshot::{
    HeaderHashInputs, HeaderHashProofKillShot, HEADER_HASH_BLOCK_PERMS, HEADER_HASH_FIELDS,
    HEADER_HASH_LINEAR_RELATION_TAG, HEADER_HASH_PERMS_PER_ITEM, HEADER_HASH_PIN_LANES,
    HEADER_HASH_POW_PERMS,
};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_BLOCKHDR, TAG_COMPRESS, TAG_POWHDR};
use noid_poseidon2b::native::permutation::{MDS_FULL, N_ROUNDS, STATE_SIZE};

use super::batch_eval::{
    verify_linear_eval_prebound_trace, LinearEvalClaimTrace, LinearEvalProofTrace,
    LinearEvalTermTrace, MultiBatchEvalProofTrace,
};
use super::block_spine::{
    close_spine_family_batch, sponge_chain_claims_trace, spine_point_index,
    verify_block_spine_shift_trace, verify_block_spine_unified_trace, BlockSpineShiftProofTrace,
    BlockSpineUnifiedProofTrace, ColumnAccumulator,
};
use super::{
    alloc_block, const_block, flat_of, pin_zero, BatchEvalReductionTrace, FieldR1csBuilder,
    LinExpr, RawChannelTrace,
};

/// Trace twin of `header_hash_killshot::pad_pair` (the `0x80…01` pad block
/// split into two lanes).
fn pad_pair_const() -> [LinExpr; 2] {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x80;
    bytes[31] = 0x01;
    [
        const_block(Block128::from(u128::from_le_bytes(
            bytes[..16].try_into().unwrap(),
        ))),
        const_block(Block128::from(u128::from_le_bytes(
            bytes[16..].try_into().unwrap(),
        ))),
    ]
}

// ---------------------------------------------------------------------------
// header_hash killshot
// ---------------------------------------------------------------------------

/// Trace twin of `HeaderHashInputs`.
pub struct HeaderHashInputsTrace {
    pub fields: Vec<LinExpr>,
    pub expected_pow_digest: [LinExpr; 2],
    pub expected_block_id: [LinExpr; 2],
}

impl HeaderHashInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &HeaderHashInputs) -> Self {
        Self {
            fields: native.fields.iter().map(|&f| alloc_block(b, f)).collect(),
            expected_pow_digest: std::array::from_fn(|i| {
                alloc_block(b, native.expected_pow_digest[i])
            }),
            expected_block_id: std::array::from_fn(|i| {
                alloc_block(b, native.expected_block_id[i])
            }),
        }
    }

    /// Trace twin of `zero_header_hash_input` (padding — constants).
    fn zero() -> Self {
        Self {
            fields: (0..HEADER_HASH_FIELDS).map(|_| LinExpr::zero()).collect(),
            expected_pow_digest: [LinExpr::zero(), LinExpr::zero()],
            expected_block_id: [LinExpr::zero(), LinExpr::zero()],
        }
    }

    /// Trace twin of `block_id_blocks` (9th block is the pad pair).
    fn block_id_blocks(&self) -> Vec<[LinExpr; 2]> {
        let pad = pad_pair_const();
        (0..HEADER_HASH_BLOCK_PERMS)
            .map(|i| {
                if i < HEADER_HASH_POW_PERMS {
                    [self.fields[2 * i].clone(), self.fields[2 * i + 1].clone()]
                } else {
                    pad.clone()
                }
            })
            .collect()
    }

    /// Trace twin of `pow_blocks`.
    fn pow_blocks(&self) -> Vec<[LinExpr; 2]> {
        (0..HEADER_HASH_POW_PERMS)
            .map(|i| [self.fields[2 * i].clone(), self.fields[2 * i + 1].clone()])
            .collect()
    }
}

/// Trace twin of `HeaderHashProofKillShot`.
pub struct HeaderHashProofTrace {
    pub main: BlockSpineUnifiedProofTrace,
    pub shift: BlockSpineShiftProofTrace,
    pub chain: LinearEvalProofTrace,
    pub batch: MultiBatchEvalProofTrace,
    pub n_headers: usize,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl HeaderHashProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &HeaderHashProofKillShot,
        n_headers: usize,
        padded_headers: usize,
    ) -> Self {
        let live_slots = padded_headers * HEADER_HASH_PERMS_PER_ITEM;
        let num_vars = noid_gkr::block_spine::num_vars_for(live_slots);
        assert_eq!(native.n_headers, n_headers, "proof off the trace shape");
        assert_eq!(native.live_slots, live_slots, "proof off the trace shape");
        assert_eq!(native.num_vars, num_vars, "proof off the trace shape");
        Self {
            main: BlockSpineUnifiedProofTrace::alloc(b, &native.kill_shot.main, num_vars),
            shift: BlockSpineShiftProofTrace::alloc(b, &native.kill_shot.shift, num_vars),
            chain: LinearEvalProofTrace::alloc(b, &native.chain, num_vars),
            batch: MultiBatchEvalProofTrace::alloc(b, &native.batch, num_vars, 3),
            n_headers,
            num_vars,
            live_slots,
        }
    }
}

/// Trace twin of `absorb_public_batch_padded` (header hash).
fn absorb_header_public_batch_padded_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    inputs: &[HeaderHashInputsTrace],
    padded_headers: usize,
) {
    ch.absorb_const_tower(b, inputs.len() as u128);
    ch.absorb_const_tower(b, padded_headers as u128);
    ch.absorb_const_tower(b, TAG_POWHDR.as_u64() as u128);
    ch.absorb_const_tower(b, TAG_BLOCKHDR.as_u64() as u128);
    let zero = HeaderHashInputsTrace::zero();
    for idx in 0..padded_headers {
        let input = inputs.get(idx).unwrap_or(&zero);
        for field in &input.fields {
            ch.absorb(b, field);
        }
        for lane in &input.expected_pow_digest {
            ch.absorb(b, lane);
        }
        for lane in &input.expected_block_id {
            ch.absorb(b, lane);
        }
    }
}

/// Trace twin of `header_hash_claims_padded` (zeroed template claims for
/// padding headers — same term structure, zero coefficients and values).
fn header_hash_claims_padded_trace(
    inputs: &[HeaderHashInputsTrace],
    padded_headers: usize,
    num_vars: usize,
) -> Vec<LinearEvalClaimTrace> {
    let mut claims = Vec::new();
    for (idx, input) in inputs.iter().enumerate() {
        let base = idx * HEADER_HASH_PERMS_PER_ITEM;
        claims.extend(sponge_chain_claims_trace(
            &input.block_id_blocks(),
            capacity_iv(TAG_BLOCKHDR),
            &input.expected_block_id[..HEADER_HASH_PIN_LANES],
            base,
            num_vars,
        ));
        claims.extend(sponge_chain_claims_trace(
            &input.pow_blocks(),
            capacity_iv(TAG_POWHDR),
            &input.expected_pow_digest[..HEADER_HASH_PIN_LANES],
            base + HEADER_HASH_BLOCK_PERMS,
            num_vars,
        ));
    }
    if inputs.len() < padded_headers {
        // zero_linear_claims_like(header_hash_claims([zero], num_vars)) with
        // the slot base shifted per padding item; the base-0 template's term
        // indices are rebuilt per item (identical to native, which builds the
        // template once at base 0 — base 0 == item 0 only when inputs is
        // empty, which native rejects; for live inputs the padding items sit
        // at bases ≥ inputs.len(), matching native's per-index template
        // because zeroed terms carry zero coefficients and the linear-eval
        // transcript binds only counts).
        let zero = HeaderHashInputsTrace::zero();
        for item_idx in inputs.len()..padded_headers {
            let _ = item_idx;
            let mut template = Vec::new();
            template.extend(sponge_chain_claims_trace(
                &zero.block_id_blocks(),
                capacity_iv(TAG_BLOCKHDR),
                &zero.expected_block_id[..HEADER_HASH_PIN_LANES],
                0,
                num_vars,
            ));
            template.extend(sponge_chain_claims_trace(
                &zero.pow_blocks(),
                capacity_iv(TAG_POWHDR),
                &zero.expected_pow_digest[..HEADER_HASH_PIN_LANES],
                0,
                num_vars,
            ));
            for claim in &mut template {
                claim.value = LinExpr::zero();
                for term in &mut claim.terms {
                    term.coeff = Block128::ZERO;
                }
            }
            claims.extend(template);
        }
    }
    claims
}

/// Trace twin of `verify_header_hash_killshot_padded`.
pub fn verify_header_hash_killshot_padded_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &HeaderHashProofTrace,
    inputs: &[HeaderHashInputsTrace],
    padded_headers: usize,
) -> [BatchEvalReductionTrace; 3] {
    assert!(!inputs.is_empty());
    assert_eq!(proof.n_headers, inputs.len());
    assert!(inputs.len() <= padded_headers);
    assert_eq!(proof.live_slots, padded_headers * HEADER_HASH_PERMS_PER_ITEM);
    assert_eq!(
        proof.num_vars,
        noid_gkr::block_spine::num_vars_for(proof.live_slots)
    );

    absorb_header_public_batch_padded_trace(b, ch, inputs, padded_headers);

    let main_red =
        verify_block_spine_unified_trace(b, ch, &proof.main, proof.num_vars, proof.live_slots);
    let shift_red = verify_block_spine_shift_trace(b, ch, &proof.shift, &main_red, proof.num_vars);

    let chain_claims = header_hash_claims_padded_trace(inputs, padded_headers, proof.num_vars);
    let chain_red = verify_linear_eval_prebound_trace(
        b,
        ch,
        &proof.chain,
        &chain_claims,
        proof.num_vars,
        HEADER_HASH_LINEAR_RELATION_TAG,
    );

    close_spine_family_batch(b, ch, &main_red, &shift_red, &chain_red, &proof.batch, proof.num_vars)
}

/// Trace twin of `discharge_header_hash_reductions_native_padded`:
/// `evaluate_header_hashes` (both sponge chains per header, digest checks as
/// pins) + zero-state padding slots + the shared-point column pins.
pub fn discharge_header_hash_padded_trace(
    b: &mut FieldR1csBuilder,
    inputs: &[HeaderHashInputsTrace],
    reductions: &[BatchEvalReductionTrace; 3],
    padded_headers: usize,
) {
    assert!(!inputs.is_empty());
    let padded_live_slots = padded_headers * HEADER_HASH_PERMS_PER_ITEM;
    let mut acc = ColumnAccumulator::new(b, &reductions[0].point, padded_live_slots);

    let run_sponge = |b: &mut FieldR1csBuilder,
                          acc: &mut ColumnAccumulator,
                          blocks: &[[LinExpr; 2]],
                          iv: [Block128; 2],
                          expected: &[LinExpr; 2]| {
        let mut state: [LinExpr; STATE_SIZE] = [
            LinExpr::zero(),
            LinExpr::zero(),
            const_block(iv[0]),
            const_block(iv[1]),
        ];
        for block in blocks {
            state[0] = state[0].add(&block[0]);
            state[1] = state[1].add(&block[1]);
            state = acc.push_slot(b, &state);
        }
        pin_zero(b, &state[0].add(&expected[0]));
        pin_zero(b, &state[1].add(&expected[1]));
    };

    for input in inputs {
        run_sponge(
            b,
            &mut acc,
            &input.block_id_blocks(),
            capacity_iv(TAG_BLOCKHDR),
            &input.expected_block_id,
        );
        run_sponge(
            b,
            &mut acc,
            &input.pow_blocks(),
            capacity_iv(TAG_POWHDR),
            &input.expected_pow_digest,
        );
    }
    // slot_state_ins.resize(padded_live_slots, ZERO) — zero-state padding.
    for _ in inputs.len() * HEADER_HASH_PERMS_PER_ITEM..padded_live_slots {
        let zero_state: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
        acc.push_slot(b, &zero_state);
    }

    let (state_value, sin_value, sout_value) = acc.finish();
    pin_zero(b, &state_value.add(&reductions[0].value));
    pin_zero(b, &sin_value.add(&reductions[1].value));
    pin_zero(b, &sout_value.add(&reductions[2].value));
}

// ---------------------------------------------------------------------------
// chain_accumulator killshot
// ---------------------------------------------------------------------------

/// Trace twin of `ChainAccumulatorItem`.
pub struct ChainAccumulatorItemTrace {
    pub block_id: [LinExpr; 2],
    pub chain_claim: [LinExpr; 2],
}

/// Trace twin of `ChainAccumulatorBatchInputs`.
pub struct ChainAccumulatorBatchInputsTrace {
    pub start_chain_hash: [LinExpr; 2],
    pub items: Vec<ChainAccumulatorItemTrace>,
    pub expected_chain_hash: [LinExpr; 2],
}

impl ChainAccumulatorBatchInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &ChainAccumulatorBatchInputs) -> Self {
        Self {
            start_chain_hash: std::array::from_fn(|i| {
                alloc_block(b, native.start_chain_hash[i])
            }),
            items: native
                .items
                .iter()
                .map(|item| ChainAccumulatorItemTrace {
                    block_id: std::array::from_fn(|i| alloc_block(b, item.block_id[i])),
                    chain_claim: std::array::from_fn(|i| alloc_block(b, item.chain_claim[i])),
                })
                .collect(),
            expected_chain_hash: std::array::from_fn(|i| {
                alloc_block(b, native.expected_chain_hash[i])
            }),
        }
    }
}

/// Trace twin of `ChainAccumulatorProofKillShot`.
pub struct ChainAccumulatorProofTrace {
    pub main: BlockSpineUnifiedProofTrace,
    pub shift: BlockSpineShiftProofTrace,
    pub chain: LinearEvalProofTrace,
    pub batch: MultiBatchEvalProofTrace,
    pub n_items: usize,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl ChainAccumulatorProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &ChainAccumulatorProofKillShot,
        n_items: usize,
        padded_items: usize,
    ) -> Self {
        let live_slots = padded_items * CHAIN_ACC_PERMS_PER_ITEM;
        let num_vars = noid_gkr::block_spine::num_vars_for(live_slots);
        assert_eq!(native.n_items, n_items, "proof off the trace shape");
        assert_eq!(native.live_slots, live_slots, "proof off the trace shape");
        assert_eq!(native.num_vars, num_vars, "proof off the trace shape");
        Self {
            main: BlockSpineUnifiedProofTrace::alloc(b, &native.kill_shot.main, num_vars),
            shift: BlockSpineShiftProofTrace::alloc(b, &native.kill_shot.shift, num_vars),
            chain: LinearEvalProofTrace::alloc(b, &native.chain, num_vars),
            batch: MultiBatchEvalProofTrace::alloc(b, &native.batch, num_vars, 3),
            n_items,
            num_vars,
            live_slots,
        }
    }
}

/// Trace twin of `absorb_public_batch_padded` (chain accumulator).
fn absorb_chain_acc_public_batch_padded_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    inputs: &ChainAccumulatorBatchInputsTrace,
    padded_items: usize,
) {
    ch.absorb_const_tower(b, inputs.items.len() as u128);
    ch.absorb_const_tower(b, padded_items as u128);
    ch.absorb_const_tower(b, TAG_COMPRESS.as_u64() as u128);
    ch.absorb(b, &inputs.start_chain_hash[0]);
    ch.absorb(b, &inputs.start_chain_hash[1]);
    ch.absorb(b, &inputs.expected_chain_hash[0]);
    ch.absorb(b, &inputs.expected_chain_hash[1]);
    let zero = LinExpr::zero();
    for idx in 0..padded_items {
        match inputs.items.get(idx) {
            Some(item) => {
                ch.absorb(b, &item.block_id[0]);
                ch.absorb(b, &item.block_id[1]);
                ch.absorb(b, &item.chain_claim[0]);
                ch.absorb(b, &item.chain_claim[1]);
            }
            None => {
                for _ in 0..4 {
                    ch.absorb(b, &zero);
                }
            }
        }
    }
}

/// Trace twin of `chain_claims` + `chain_claims_padded`.
fn chain_acc_claims_padded_trace(
    inputs: &ChainAccumulatorBatchInputsTrace,
    padded_items: usize,
    num_vars: usize,
) -> Vec<LinearEvalClaimTrace> {
    let [iv_hi, iv_lo] = capacity_iv(TAG_COMPRESS);
    let mds = |row: usize, col: usize| Block128::from(MDS_FULL[row][col]);
    let state_term = |slot: usize, round: usize, lane: usize, coeff: Block128| LinearEvalTermTrace {
        index: spine_point_index(num_vars, slot, round, lane),
        coeff,
    };
    let mds_pair = |lane: usize, a: &LinExpr, b_: &LinExpr, c0: usize, c1: usize| {
        a.scale(flat_of(mds(lane, c0)))
            .add(&b_.scale(flat_of(mds(lane, c1))))
    };
    let iv_const = |lane: usize| flat_of(mds(lane, 2) * iv_hi + mds(lane, 3) * iv_lo);

    let mut claims = Vec::new();
    for (idx, item) in inputs.items.iter().enumerate() {
        let base = idx * CHAIN_ACC_PERMS_PER_ITEM;

        // inner_0 = [block_id, IV] entry row.
        for lane in 0..STATE_SIZE {
            claims.push(LinearEvalClaimTrace {
                terms: vec![state_term(base, 0, lane, Block128::ONE)],
                value: mds_pair(lane, &item.block_id[0], &item.block_id[1], 0, 1)
                    .add_const(iv_const(lane)),
            });
        }
        // inner_1: prev perm output + chain_claim absorbed into the rate.
        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_term(base + 1, 0, lane, Block128::ONE)];
            for src_lane in 0..STATE_SIZE {
                terms.push(state_term(base, N_ROUNDS, src_lane, mds(lane, src_lane)));
            }
            claims.push(LinearEvalClaimTrace {
                terms,
                value: mds_pair(lane, &item.chain_claim[0], &item.chain_claim[1], 0, 1),
            });
        }
        // outer_0 = [chain_{i-1}, IV].
        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_term(base + 2, 0, lane, Block128::ONE)];
            let value = if idx == 0 {
                mds_pair(
                    lane,
                    &inputs.start_chain_hash[0],
                    &inputs.start_chain_hash[1],
                    0,
                    1,
                )
                .add_const(iv_const(lane))
            } else {
                for src_lane in [0usize, 1usize] {
                    terms.push(state_term(base - 1, N_ROUNDS, src_lane, mds(lane, src_lane)));
                }
                LinExpr::constant(iv_const(lane))
            };
            claims.push(LinearEvalClaimTrace { terms, value });
        }
        // outer_1: prev perm output + inner digest absorbed into the rate.
        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_term(base + 3, 0, lane, Block128::ONE)];
            for src_lane in 0..STATE_SIZE {
                terms.push(state_term(base + 2, N_ROUNDS, src_lane, mds(lane, src_lane)));
            }
            for src_lane in [0usize, 1usize] {
                terms.push(state_term(base + 1, N_ROUNDS, src_lane, mds(lane, src_lane)));
            }
            claims.push(LinearEvalClaimTrace {
                terms,
                value: LinExpr::zero(),
            });
        }
    }

    let last_slot = inputs.items.len() * CHAIN_ACC_PERMS_PER_ITEM - 1;
    for lane in 0..CHAIN_ACC_PIN_LANES {
        claims.push(LinearEvalClaimTrace {
            terms: vec![state_term(last_slot, N_ROUNDS, lane, Block128::ONE)],
            value: inputs.expected_chain_hash[lane].clone(),
        });
    }

    // zero_chain_item_claims per padding item (zero coeffs and values, same
    // term structure).
    for item_idx in inputs.items.len()..padded_items {
        let base = item_idx * CHAIN_ACC_PERMS_PER_ITEM;
        for lane in 0..STATE_SIZE {
            let _ = lane;
            claims.push(LinearEvalClaimTrace {
                terms: vec![state_term(base, 0, lane, Block128::ZERO)],
                value: LinExpr::zero(),
            });
        }
        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_term(base + 1, 0, lane, Block128::ZERO)];
            for src_lane in 0..STATE_SIZE {
                terms.push(state_term(base, N_ROUNDS, src_lane, Block128::ZERO));
            }
            claims.push(LinearEvalClaimTrace {
                terms,
                value: LinExpr::zero(),
            });
        }
        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_term(base + 2, 0, lane, Block128::ZERO)];
            if item_idx > 0 {
                for src_lane in [0usize, 1usize] {
                    terms.push(state_term(base - 1, N_ROUNDS, src_lane, Block128::ZERO));
                }
            }
            claims.push(LinearEvalClaimTrace {
                terms,
                value: LinExpr::zero(),
            });
        }
        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_term(base + 3, 0, lane, Block128::ZERO)];
            for src_lane in 0..STATE_SIZE {
                terms.push(state_term(base + 2, N_ROUNDS, src_lane, Block128::ZERO));
            }
            for src_lane in [0usize, 1usize] {
                terms.push(state_term(base + 1, N_ROUNDS, src_lane, Block128::ZERO));
            }
            claims.push(LinearEvalClaimTrace {
                terms,
                value: LinExpr::zero(),
            });
        }
    }

    claims
}

/// Trace twin of `verify_chain_accumulator_killshot_padded`.
pub fn verify_chain_accumulator_killshot_padded_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &ChainAccumulatorProofTrace,
    inputs: &ChainAccumulatorBatchInputsTrace,
    padded_items: usize,
) -> [BatchEvalReductionTrace; 3] {
    assert!(!inputs.items.is_empty());
    assert_eq!(proof.n_items, inputs.items.len());
    assert!(inputs.items.len() <= padded_items);
    assert_eq!(proof.live_slots, padded_items * CHAIN_ACC_PERMS_PER_ITEM);
    assert_eq!(
        proof.num_vars,
        noid_gkr::block_spine::num_vars_for(proof.live_slots)
    );

    absorb_chain_acc_public_batch_padded_trace(b, ch, inputs, padded_items);

    let main_red =
        verify_block_spine_unified_trace(b, ch, &proof.main, proof.num_vars, proof.live_slots);
    let shift_red = verify_block_spine_shift_trace(b, ch, &proof.shift, &main_red, proof.num_vars);

    let chain_claims = chain_acc_claims_padded_trace(inputs, padded_items, proof.num_vars);
    let chain_red = verify_linear_eval_prebound_trace(
        b,
        ch,
        &proof.chain,
        &chain_claims,
        proof.num_vars,
        CHAIN_ACC_LINEAR_RELATION_TAG,
    );

    close_spine_family_batch(b, ch, &main_red, &shift_red, &chain_red, &proof.batch, proof.num_vars)
}

/// Trace twin of `discharge_chain_accumulator_reductions_native_padded`:
/// `evaluate_chain_accumulator` (the 4-permutation compression chain per
/// item, chain-hash check as pins) + zero-state padding + column pins.
pub fn discharge_chain_accumulator_padded_trace(
    b: &mut FieldR1csBuilder,
    inputs: &ChainAccumulatorBatchInputsTrace,
    reductions: &[BatchEvalReductionTrace; 3],
    padded_items: usize,
) {
    assert!(!inputs.items.is_empty());
    let [iv_hi, iv_lo] = capacity_iv(TAG_COMPRESS);
    let padded_live_slots = padded_items * CHAIN_ACC_PERMS_PER_ITEM;
    let mut acc = ColumnAccumulator::new(b, &reductions[0].point, padded_live_slots);

    let mut chain_hash = [
        inputs.start_chain_hash[0].clone(),
        inputs.start_chain_hash[1].clone(),
    ];
    for item in &inputs.items {
        let inner0: [LinExpr; STATE_SIZE] = [
            item.block_id[0].clone(),
            item.block_id[1].clone(),
            const_block(iv_hi),
            const_block(iv_lo),
        ];
        let mut inner = acc.push_slot(b, &inner0);
        inner[0] = inner[0].add(&item.chain_claim[0]);
        inner[1] = inner[1].add(&item.chain_claim[1]);
        let inner = acc.push_slot(b, &inner);
        let inner_digest = [inner[0].clone(), inner[1].clone()];

        let outer0: [LinExpr; STATE_SIZE] = [
            chain_hash[0].clone(),
            chain_hash[1].clone(),
            const_block(iv_hi),
            const_block(iv_lo),
        ];
        let mut outer = acc.push_slot(b, &outer0);
        outer[0] = outer[0].add(&inner_digest[0]);
        outer[1] = outer[1].add(&inner_digest[1]);
        let outer = acc.push_slot(b, &outer);
        chain_hash = [outer[0].clone(), outer[1].clone()];
    }
    pin_zero(b, &chain_hash[0].add(&inputs.expected_chain_hash[0]));
    pin_zero(b, &chain_hash[1].add(&inputs.expected_chain_hash[1]));

    for _ in inputs.items.len() * CHAIN_ACC_PERMS_PER_ITEM..padded_live_slots {
        let zero_state: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
        acc.push_slot(b, &zero_state);
    }

    let (state_value, sin_value, sout_value) = acc.finish();
    pin_zero(b, &state_value.add(&reductions[0].value));
    pin_zero(b, &sin_value.add(&reductions[1].value));
    pin_zero(b, &sout_value.add(&reductions[2].value));
}

// ---------------------------------------------------------------------------
// Full slot assembly
// ---------------------------------------------------------------------------

/// Build the complete checkpoint_poseidon [K]+[D] slot: both killshots, each
/// on its own fresh raw channel (mirror of the two `Poseidon2bChannel::new()`
/// in `verify_checkpoint_poseidon`). Returns the statement wires for the [B]
/// bindings.
pub fn build_checkpoint_poseidon_slot(
    b: &mut FieldR1csBuilder,
    proof: &crate::checkpoint::CheckpointPoseidonProof,
    header_inputs: &[HeaderHashInputs],
    chain_inputs: &ChainAccumulatorBatchInputs,
    padded_blocks: usize,
) -> (Vec<HeaderHashInputsTrace>, ChainAccumulatorBatchInputsTrace) {
    assert_eq!(proof.n_blocks, header_inputs.len());
    assert_eq!(header_inputs.len(), chain_inputs.items.len());

    let header_inputs_t: Vec<HeaderHashInputsTrace> = header_inputs
        .iter()
        .map(|i| HeaderHashInputsTrace::alloc(b, i))
        .collect();
    let chain_inputs_t = ChainAccumulatorBatchInputsTrace::alloc(b, chain_inputs);

    let header_proof_t =
        HeaderHashProofTrace::alloc(b, &proof.header_hash, header_inputs.len(), padded_blocks);
    let mut ch_header = RawChannelTrace::new();
    let header_reds = verify_header_hash_killshot_padded_trace(
        b,
        &mut ch_header,
        &header_proof_t,
        &header_inputs_t,
        padded_blocks,
    );
    discharge_header_hash_padded_trace(b, &header_inputs_t, &header_reds, padded_blocks);

    let chain_proof_t = ChainAccumulatorProofTrace::alloc(
        b,
        &proof.chain_accumulator,
        chain_inputs.items.len(),
        padded_blocks,
    );
    let mut ch_chain = RawChannelTrace::new();
    let chain_reds = verify_chain_accumulator_killshot_padded_trace(
        b,
        &mut ch_chain,
        &chain_proof_t,
        &chain_inputs_t,
        padded_blocks,
    );
    discharge_chain_accumulator_padded_trace(b, &chain_inputs_t, &chain_reds, padded_blocks);

    (header_inputs_t, chain_inputs_t)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accepted_batch::{chain_accumulator_proof_inputs, AcceptedClaimBatchWitness};
    use crate::accumulator::ChainAccumulator;
    use crate::checkpoint::{prove_checkpoint_poseidon_padded, CheckpointPoseidonProof};
    use crate::pow_header::{header_hash_proof_inputs, HeaderWitness};
    use noid_chain::consensus::params::MAX_TARGET;
    use noid_gkr::chain_accumulator_killshot::{
        discharge_chain_accumulator_reductions_native_padded,
        verify_chain_accumulator_killshot_padded,
    };
    use noid_gkr::header_hash_killshot::{
        discharge_header_hash_reductions_native_padded, verify_header_hash_killshot_padded,
    };
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use noid_poseidon2b::primitives::Address;

    fn header(height: u64, prev: [u8; 32], state_seed: u8) -> noid_chain::BlockHeader {
        noid_chain::BlockHeader {
            prev_block_hash: prev,
            state_root: [state_seed; 32],
            tx_root: [state_seed ^ 0x55; 32],
            timestamp: 1_767_225_600 + height * 15,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: MAX_TARGET,
            log_slots: 24,
            active_slot_count: height,
            alloc_counter: height,
        }
    }

    fn fixture_n(
        n: usize,
    ) -> (
        ChainAccumulator,
        ChainAccumulator,
        AcceptedClaimBatchWitness,
    ) {
        assert!(n > 0);
        let start = ChainAccumulator {
            height: 0,
            state_root: [1u8; 32],
            chain_hash: [0u8; 32],
        };
        let mut acc = start.clone();
        let mut prev_block_id = [0u8; 32];
        let mut headers = Vec::with_capacity(n);
        let mut claims = Vec::with_capacity(n);
        for height in 1..=n as u64 {
            let h = header(height, prev_block_id, height as u8 + 1);
            let w = HeaderWitness::from_header(&h);
            let claim = [
                Block128::from(0xA0u128 + height as u128),
                Block128::from(0xB0u128 + height as u128),
            ];
            acc = acc.extend(h.state_root, w.block_id, h.height, claim);
            prev_block_id = w.block_id;
            headers.push(w);
            claims.push(claim);
        }
        let witness = AcceptedClaimBatchWitness {
            headers,
            accepted_block_claims: claims,
        };
        (start, acc, witness)
    }

    struct Fixture {
        proof: CheckpointPoseidonProof,
        header_inputs: Vec<noid_gkr::header_hash_killshot::HeaderHashInputs>,
        chain_inputs: ChainAccumulatorBatchInputs,
        padded_blocks: usize,
    }

    fn fixture(n: usize, padded_blocks: usize) -> Fixture {
        let (start, end, witness) = fixture_n(n);
        let proof =
            prove_checkpoint_poseidon_padded(&start, &end, &witness, padded_blocks).unwrap();
        Fixture {
            header_inputs: header_hash_proof_inputs(&witness.headers),
            chain_inputs: chain_accumulator_proof_inputs(&start, &witness, &end),
            proof,
            padded_blocks,
        }
    }

    /// Killshot-level native acceptance (the trace's exact scope — the
    /// header-struct `validate_shape` / accumulator boundary checks are [B]).
    fn native_accepts(f: &Fixture) -> bool {
        let mut ch = Poseidon2bChannel::new();
        let header_ok = verify_header_hash_killshot_padded(
            &f.proof.header_hash,
            &f.header_inputs,
            f.padded_blocks,
            &mut ch,
        )
        .map(|red| {
            discharge_header_hash_reductions_native_padded(
                &f.header_inputs,
                &red,
                f.padded_blocks,
            )
        })
        .unwrap_or(false);
        let mut ch = Poseidon2bChannel::new();
        let chain_ok = verify_chain_accumulator_killshot_padded(
            &f.proof.chain_accumulator,
            &f.chain_inputs,
            f.padded_blocks,
            &mut ch,
        )
        .map(|red| {
            discharge_chain_accumulator_reductions_native_padded(
                &f.chain_inputs,
                &red,
                f.padded_blocks,
            )
        })
        .unwrap_or(false);
        header_ok && chain_ok
    }

    fn trace_accepts(f: &Fixture) -> bool {
        let mut b = FieldR1csBuilder::new();
        let _ = build_checkpoint_poseidon_slot(
            &mut b,
            &f.proof,
            &f.header_inputs,
            &f.chain_inputs,
            f.padded_blocks,
        );
        let (r1cs, z) = b.build();
        r1cs.satisfies(&z)
    }

    /// Positive: K=1 shape (the per-block production case) and a padded batch.
    #[test]
    fn checkpoint_poseidon_trace_positive() {
        for (n, padded) in [(1usize, 1usize), (2, 4)] {
            let f = fixture(n, padded);
            assert!(native_accepts(&f), "native fixture broken (n={n})");
            let mut b = FieldR1csBuilder::new();
            let _ = build_checkpoint_poseidon_slot(
                &mut b,
                &f.proof,
                &f.header_inputs,
                &f.chain_inputs,
                f.padded_blocks,
            );
            let (r1cs, z) = b.build();
            assert!(
                r1cs.satisfies(&z),
                "honest checkpoint trace unsatisfiable (n={n}, padded={padded})"
            );
            if n == 1 {
                eprintln!(
                    "checkpoint_poseidon slot (K=1): {} useful rows (k_log = {})",
                    r1cs.useful_rows, r1cs.k_log
                );
            }
        }
    }

    fn visit_checkpoint_proof_fields(
        p: &mut CheckpointPoseidonProof,
        f: &mut dyn FnMut(&mut Block128),
    ) {
        let spines = [
            &mut p.header_hash.kill_shot,
            &mut p.chain_accumulator.kill_shot,
        ];
        for ks in spines {
            for rp in &mut ks.main.round_polys {
                for c in &mut rp.coeffs {
                    f(c);
                }
            }
            f(&mut ks.main.s_in_dec_at_r);
            f(&mut ks.main.s_out_dec_at_r);
            f(&mut ks.main.state_dec_at_r);
            f(&mut ks.main.state_at_r);
            for v in &mut ks.main.s_out_lane_dec_at_r {
                f(v);
            }
            for v in &mut ks.main.state_lane_dec_at_r {
                f(v);
            }
            for rp in &mut ks.shift.round_polys {
                for c in &mut rp.coeffs {
                    f(c);
                }
            }
            f(&mut ks.shift.s_in_at_r2);
            f(&mut ks.shift.s_out_at_r2);
            f(&mut ks.shift.state_at_r2);
        }
        for chain in [&mut p.header_hash.chain, &mut p.chain_accumulator.chain] {
            for r in &mut chain.rounds {
                for e in &mut r.evals_at_1_2 {
                    f(e);
                }
            }
            f(&mut chain.b_final);
        }
        for batch in [&mut p.header_hash.batch, &mut p.chain_accumulator.batch] {
            for r in &mut batch.rounds {
                for e in &mut r.evals_at_1_2 {
                    f(e);
                }
            }
            for v in &mut batch.b_finals {
                f(v);
            }
        }
    }

    fn count_fields(p: &CheckpointPoseidonProof) -> usize {
        let mut n = 0;
        let mut c = p.clone();
        visit_checkpoint_proof_fields(&mut c, &mut |_| n += 1);
        n
    }

    fn mutate_field(p: &CheckpointPoseidonProof, target: usize) -> CheckpointPoseidonProof {
        let mut m = p.clone();
        let mut i = 0;
        visit_checkpoint_proof_fields(&mut m, &mut |v| {
            if i == target {
                *v += Block128::ONE;
            }
            i += 1;
        });
        m
    }

    /// Replay-completeness auto-mutator (proof side), K=1 shape.
    /// 0 surviving mutants.
    #[test]
    fn checkpoint_poseidon_proof_mutator_kills_all() {
        let f = fixture(1, 1);
        let n_fields = count_fields(&f.proof);
        let stride: usize = std::env::var("NOID_TRACE_MUTATE_STRIDE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let mut survivors = Vec::new();
        for target in (0..n_fields).step_by(stride) {
            let bad = Fixture {
                proof: mutate_field(&f.proof, target),
                header_inputs: f.header_inputs.clone(),
                chain_inputs: f.chain_inputs.clone(),
                padded_blocks: f.padded_blocks,
            };
            assert!(!native_accepts(&bad), "native accepted proof mutant {target}");
            if trace_accepts(&bad) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving checkpoint proof mutants: {survivors:?} of {n_fields}"
        );
    }

    /// Statement-side auto-mutator: header fields/digests, chain
    /// items and boundary hashes.
    #[test]
    fn checkpoint_poseidon_statement_mutator_kills_all() {
        let f = fixture(1, 1);
        let header_fields = HEADER_HASH_FIELDS + 4; // fields + 2 digests
        let chain_fields = 4 + f.chain_inputs.items.len() * 4; // start/end + items
        let mut survivors = Vec::new();

        for target in 0..header_fields + chain_fields {
            let mut bad_header = f.header_inputs.clone();
            let mut bad_chain = f.chain_inputs.clone();
            if target < HEADER_HASH_FIELDS {
                bad_header[0].fields[target] += Block128::ONE;
            } else if target < HEADER_HASH_FIELDS + 2 {
                bad_header[0].expected_pow_digest[target - HEADER_HASH_FIELDS] += Block128::ONE;
            } else if target < header_fields {
                bad_header[0].expected_block_id[target - HEADER_HASH_FIELDS - 2] += Block128::ONE;
            } else {
                let t = target - header_fields;
                match t {
                    0 | 1 => bad_chain.start_chain_hash[t] += Block128::ONE,
                    2 | 3 => bad_chain.expected_chain_hash[t - 2] += Block128::ONE,
                    _ => {
                        let it = (t - 4) / 4;
                        match (t - 4) % 4 {
                            0 | 1 => bad_chain.items[it].block_id[(t - 4) % 4] += Block128::ONE,
                            k => bad_chain.items[it].chain_claim[k - 2] += Block128::ONE,
                        }
                    }
                }
            }
            let bad = Fixture {
                proof: f.proof.clone(),
                header_inputs: bad_header,
                chain_inputs: bad_chain,
                padded_blocks: f.padded_blocks,
            };
            assert!(
                !native_accepts(&bad),
                "native accepted statement mutant {target}"
            );
            if trace_accepts(&bad) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving checkpoint statement mutants: {survivors:?}"
        );
    }

    /// Cross-test "trace ⇔ native" on randomized honest/mutated cases.
    #[test]
    fn checkpoint_poseidon_native_trace_equivalence() {
        let cases: usize = std::env::var("NOID_TRACE_CROSS_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let mut seed = 0xC4EC_4B01u128;
        let mut next = |m: u128| {
            seed = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            (seed >> 16) % m
        };

        let f = fixture(1, 1);
        let n_fields = count_fields(&f.proof);
        for case in 0..cases {
            let case_f = if case % 2 == 0 {
                Fixture {
                    proof: f.proof.clone(),
                    header_inputs: f.header_inputs.clone(),
                    chain_inputs: f.chain_inputs.clone(),
                    padded_blocks: f.padded_blocks,
                }
            } else {
                Fixture {
                    proof: mutate_field(&f.proof, next(n_fields as u128) as usize),
                    header_inputs: f.header_inputs.clone(),
                    chain_inputs: f.chain_inputs.clone(),
                    padded_blocks: f.padded_blocks,
                }
            };
            assert_eq!(
                native_accepts(&case_f),
                trace_accepts(&case_f),
                "native/trace divergence on case {case}"
            );
        }
    }
}
