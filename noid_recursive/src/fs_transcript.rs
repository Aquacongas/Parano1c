// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Poseidon2b Fiat-Shamir transcript proof component.
//!
//! This proves that an ordered absorb/squeeze trace is exactly the trace of the
//! production `Poseidon2bChannel`. It is a building block for recursive
//! verification of wallet authorization proofs: the final authorization
//! component must additionally prove the algebraic verifier checks that consume
//! these challenges.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_gkr::batch_eval::{
    prove_linear_eval_prebound, prove_multi_batch_eval, verify_linear_eval_prebound,
    verify_multi_batch_eval, BatchEvalReduction, EvalClaim, LinearEvalClaim, LinearEvalProof,
    LinearEvalTerm, MultiBatchEvalProof,
};
use noid_gkr::block_spine::{
    block_spine_state_point, num_vars_for, prove_block_spine_shift, prove_block_spine_unified,
    verify_block_spine_shift, verify_block_spine_unified,
};
use noid_gkr::{BlockSpineKillShotProof, BlockSpineMle, BlockSpineUnifiedReduction};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_KSCHANNL};
use noid_poseidon2b::native::permutation::{Poseidon2bPermutation, MDS_FULL, N_ROUNDS, STATE_SIZE};

use crate::authorization::FiatShamirTraceOp;

const FS_TRANSCRIPT_LINEAR_RELATION_TAG: u128 = 0x4653_5452_4143_4501; // "FSTRACE"+1
pub const FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH: usize = 16;
pub const FIAT_SHAMIR_TRANSCRIPT_MAX_OPS_PER_TRACE: usize = 4096;
pub const FIAT_SHAMIR_TRANSCRIPT_MAX_PERMUTATIONS_PER_BATCH: usize = 16384;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FiatShamirTranscriptProofKillShot {
    pub kill_shot: BlockSpineKillShotProof,
    pub chain: LinearEvalProof,
    pub batch: MultiBatchEvalProof,
    pub n_ops: usize,
    pub n_permutations: usize,
    pub num_vars: usize,
    pub live_slots: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FiatShamirTranscriptBatchProofKillShot {
    pub kill_shot: BlockSpineKillShotProof,
    pub chain: LinearEvalProof,
    pub batch: MultiBatchEvalProof,
    pub n_traces: usize,
    pub n_ops: usize,
    pub n_permutations: usize,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl FiatShamirTranscriptBatchProofKillShot {
    pub fn byte_len(&self) -> usize {
        let main_polys = self.kill_shot.main.round_polys.len()
            * noid_gkr::block_spine::BLOCK_SPINE_ROUND_DEGREE
            * 16;
        let shift_polys = self.kill_shot.shift.round_polys.len()
            * noid_gkr::block_spine::BLOCK_SPINE_SHIFT_DEGREE
            * 16;
        let main_finals = 12 * 16;
        let shift_finals = 3 * 16;
        main_polys
            + shift_polys
            + main_finals
            + shift_finals
            + self.chain.byte_len()
            + self.batch.byte_len()
    }
}

impl FiatShamirTranscriptProofKillShot {
    pub fn byte_len(&self) -> usize {
        let main_polys = self.kill_shot.main.round_polys.len()
            * noid_gkr::block_spine::BLOCK_SPINE_ROUND_DEGREE
            * 16;
        let shift_polys = self.kill_shot.shift.round_polys.len()
            * noid_gkr::block_spine::BLOCK_SPINE_SHIFT_DEGREE
            * 16;
        let main_finals = 12 * 16;
        let shift_finals = 3 * 16;
        main_polys
            + shift_polys
            + main_finals
            + shift_finals
            + self.chain.byte_len()
            + self.batch.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiatShamirTranscriptReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FiatShamirTranscriptError {
    EmptyTrace,
    TooManyTraces,
    TraceTooLong,
    TooManyPermutations,
    InvalidSqueeze,
    NoPermutation,
    ProofShape,
    ProofRejected,
}

#[derive(Debug, Clone, Copy)]
struct LaneExpr {
    constant: Block128,
    source: Option<(usize, usize)>,
}

impl LaneExpr {
    fn constant(value: Block128) -> Self {
        Self {
            constant: value,
            source: None,
        }
    }

    fn source(slot: usize, lane: usize) -> Self {
        Self {
            constant: Block128::ZERO,
            source: Some((slot, lane)),
        }
    }

    fn add_const(mut self, value: Block128) -> Self {
        self.constant += value;
        self
    }
}

type StateExpr = [LaneExpr; STATE_SIZE];

fn initial_state_expr() -> StateExpr {
    let [iv_hi, iv_lo] = capacity_iv(TAG_KSCHANNL);
    [
        LaneExpr::constant(Block128::ZERO),
        LaneExpr::constant(Block128::ZERO),
        LaneExpr::constant(iv_hi),
        LaneExpr::constant(iv_lo),
    ]
}

fn output_state_expr(slot: usize) -> StateExpr {
    std::array::from_fn(|lane| LaneExpr::source(slot, lane))
}

fn pad_second_field() -> Block128 {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x80;
    bytes[15] = 0x01;
    Block128::from(u128::from_le_bytes(bytes))
}

fn state_claim(num_vars: usize, slot: usize, round: usize, lane: usize) -> LinearEvalTerm {
    LinearEvalTerm {
        point: block_spine_state_point(num_vars, slot, round, lane),
        coeff: Block128::ONE,
    }
}

fn weighted_state_claim(
    num_vars: usize,
    slot: usize,
    round: usize,
    lane: usize,
    coeff: Block128,
) -> LinearEvalTerm {
    LinearEvalTerm {
        point: block_spine_state_point(num_vars, slot, round, lane),
        coeff,
    }
}

#[inline]
fn mds_coeff(row: usize, col: usize) -> Block128 {
    Block128::from(MDS_FULL[row][col])
}

fn push_permutation_claims(
    claims: &mut Vec<LinearEvalClaim>,
    num_vars: usize,
    slot: usize,
    input: StateExpr,
) -> StateExpr {
    for row in 0..STATE_SIZE {
        let mut terms = vec![state_claim(num_vars, slot, 0, row)];
        let mut value = Block128::ZERO;
        for (lane, expr) in input.iter().copied().enumerate() {
            let coeff = mds_coeff(row, lane);
            value += coeff * expr.constant;
            if let Some((src_slot, src_lane)) = expr.source {
                terms.push(weighted_state_claim(
                    num_vars, src_slot, N_ROUNDS, src_lane, coeff,
                ));
            }
        }
        claims.push(LinearEvalClaim { terms, value });
    }
    output_state_expr(slot)
}

fn push_expr_equals(
    claims: &mut Vec<LinearEvalClaim>,
    num_vars: usize,
    expr: LaneExpr,
    value: Block128,
) -> Result<(), FiatShamirTranscriptError> {
    match expr.source {
        Some((slot, lane)) => {
            claims.push(LinearEvalClaim {
                terms: vec![state_claim(num_vars, slot, N_ROUNDS, lane)],
                value: value + expr.constant,
            });
            Ok(())
        }
        None if expr.constant == value => Ok(()),
        None => Err(FiatShamirTranscriptError::InvalidSqueeze),
    }
}

fn trace_chain_claims(
    ops: &[FiatShamirTraceOp],
    num_vars: usize,
) -> Result<(Vec<LinearEvalClaim>, usize), FiatShamirTranscriptError> {
    trace_chain_claims_with_offset(ops, num_vars, 0)
}

fn trace_chain_claims_with_offset(
    ops: &[FiatShamirTraceOp],
    num_vars: usize,
    slot_offset: usize,
) -> Result<(Vec<LinearEvalClaim>, usize), FiatShamirTranscriptError> {
    if ops.is_empty() {
        return Err(FiatShamirTranscriptError::EmptyTrace);
    }
    if ops.len() > FIAT_SHAMIR_TRANSCRIPT_MAX_OPS_PER_TRACE {
        return Err(FiatShamirTranscriptError::TraceTooLong);
    }

    let mut claims = Vec::new();
    let mut current = initial_state_expr();
    let mut buffered: Option<Block128> = None;
    let mut pending: Option<LaneExpr> = None;
    let mut slot = slot_offset;

    for op in ops {
        match *op {
            FiatShamirTraceOp::Absorb(elem) => {
                pending = None;
                if let Some(first) = buffered.take() {
                    let input = [
                        current[0].add_const(first),
                        current[1].add_const(elem),
                        current[2],
                        current[3],
                    ];
                    current = push_permutation_claims(&mut claims, num_vars, slot, input);
                    slot += 1;
                } else {
                    buffered = Some(elem);
                }
            }
            FiatShamirTraceOp::Squeeze(value) => {
                if let Some(expr) = pending.take() {
                    push_expr_equals(&mut claims, num_vars, expr, value)?;
                    continue;
                }
                if let Some(first) = buffered.take() {
                    let input = [
                        current[0].add_const(first),
                        current[1].add_const(pad_second_field()),
                        current[2],
                        current[3],
                    ];
                    current = push_permutation_claims(&mut claims, num_vars, slot, input);
                    slot += 1;
                }

                push_expr_equals(&mut claims, num_vars, current[0], value)?;
                pending = Some(current[1]);
                current = push_permutation_claims(&mut claims, num_vars, slot, current);
                slot += 1;
            }
        }
    }

    if slot == slot_offset {
        return Err(FiatShamirTranscriptError::NoPermutation);
    }
    Ok((claims, slot - slot_offset))
}

fn evaluate_trace_permutations(
    ops: &[FiatShamirTraceOp],
) -> Result<Vec<[Block128; STATE_SIZE]>, FiatShamirTranscriptError> {
    if ops.is_empty() {
        return Err(FiatShamirTranscriptError::EmptyTrace);
    }
    if ops.len() > FIAT_SHAMIR_TRANSCRIPT_MAX_OPS_PER_TRACE {
        return Err(FiatShamirTranscriptError::TraceTooLong);
    }

    let [iv_hi, iv_lo] = capacity_iv(TAG_KSCHANNL);
    let mut state = [Block128::ZERO, Block128::ZERO, iv_hi, iv_lo];
    let mut buffered: Option<Block128> = None;
    let mut pending: Option<Block128> = None;
    let perm = Poseidon2bPermutation;
    let mut slot_state_ins = Vec::new();

    for op in ops {
        match *op {
            FiatShamirTraceOp::Absorb(elem) => {
                pending = None;
                if let Some(first) = buffered.take() {
                    state[0] += first;
                    state[1] += elem;
                    slot_state_ins.push(state);
                    perm.permute_mut(&mut state);
                } else {
                    buffered = Some(elem);
                }
            }
            FiatShamirTraceOp::Squeeze(value) => {
                if let Some(expected) = pending.take() {
                    if value != expected {
                        return Err(FiatShamirTranscriptError::InvalidSqueeze);
                    }
                    continue;
                }
                if let Some(first) = buffered.take() {
                    state[0] += first;
                    state[1] += pad_second_field();
                    slot_state_ins.push(state);
                    perm.permute_mut(&mut state);
                }
                if value != state[0] {
                    return Err(FiatShamirTranscriptError::InvalidSqueeze);
                }
                pending = Some(state[1]);
                slot_state_ins.push(state);
                perm.permute_mut(&mut state);
            }
        }
    }

    if slot_state_ins.is_empty() {
        return Err(FiatShamirTranscriptError::NoPermutation);
    }
    Ok(slot_state_ins)
}

fn absorb_trace_public<T: FiatShamir<Block128>>(channel: &mut T, ops: &[FiatShamirTraceOp]) {
    channel.absorb(Block128::from(ops.len() as u128));
    channel.absorb(Block128::from(TAG_KSCHANNL.as_u64() as u128));
    for op in ops {
        match *op {
            FiatShamirTraceOp::Absorb(value) => {
                channel.absorb(Block128::ONE);
                channel.absorb(value);
            }
            FiatShamirTraceOp::Squeeze(value) => {
                channel.absorb(Block128::from(2u128));
                channel.absorb(value);
            }
        }
    }
}

fn absorb_trace_batch_public<T: FiatShamir<Block128>>(
    channel: &mut T,
    traces: &[Vec<FiatShamirTraceOp>],
) {
    channel.absorb(Block128::from(traces.len() as u128));
    channel.absorb(Block128::from(TAG_KSCHANNL.as_u64() as u128));
    for ops in traces {
        channel.absorb(Block128::from(ops.len() as u128));
        for op in ops {
            match *op {
                FiatShamirTraceOp::Absorb(value) => {
                    channel.absorb(Block128::ONE);
                    channel.absorb(value);
                }
                FiatShamirTraceOp::Squeeze(value) => {
                    channel.absorb(Block128::from(2u128));
                    channel.absorb(value);
                }
            }
        }
    }
}

fn evaluate_trace_batch_permutations(
    traces: &[Vec<FiatShamirTraceOp>],
) -> Result<Vec<[Block128; STATE_SIZE]>, FiatShamirTranscriptError> {
    if traces.is_empty() {
        return Err(FiatShamirTranscriptError::EmptyTrace);
    }
    if traces.len() > FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH {
        return Err(FiatShamirTranscriptError::TooManyTraces);
    }
    let mut out = Vec::new();
    for ops in traces {
        out.extend(evaluate_trace_permutations(ops)?);
        if out.len() > FIAT_SHAMIR_TRANSCRIPT_MAX_PERMUTATIONS_PER_BATCH {
            return Err(FiatShamirTranscriptError::TooManyPermutations);
        }
    }
    if out.is_empty() {
        return Err(FiatShamirTranscriptError::NoPermutation);
    }
    Ok(out)
}

fn trace_batch_chain_claims(
    traces: &[Vec<FiatShamirTraceOp>],
    num_vars: usize,
) -> Result<(Vec<LinearEvalClaim>, usize, usize), FiatShamirTranscriptError> {
    if traces.is_empty() {
        return Err(FiatShamirTranscriptError::EmptyTrace);
    }
    if traces.len() > FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH {
        return Err(FiatShamirTranscriptError::TooManyTraces);
    }
    let mut all_claims = Vec::new();
    let mut slot_offset = 0usize;
    let mut n_ops = 0usize;
    for ops in traces {
        n_ops += ops.len();
        let (claims, n_perms) = trace_chain_claims_with_offset(ops, num_vars, slot_offset)?;
        all_claims.extend(claims);
        slot_offset += n_perms;
        if slot_offset > FIAT_SHAMIR_TRANSCRIPT_MAX_PERMUTATIONS_PER_BATCH {
            return Err(FiatShamirTranscriptError::TooManyPermutations);
        }
    }
    if slot_offset == 0 {
        return Err(FiatShamirTranscriptError::NoPermutation);
    }
    Ok((all_claims, n_ops, slot_offset))
}

pub fn prove_fiat_shamir_transcript_killshot<T: FiatShamir<Block128>>(
    ops: &[FiatShamirTraceOp],
    channel: &mut T,
) -> Result<
    (
        FiatShamirTranscriptProofKillShot,
        FiatShamirTranscriptReductions,
    ),
    FiatShamirTranscriptError,
> {
    let slot_state_ins = evaluate_trace_permutations(ops)?;
    let n_permutations = slot_state_ins.len();
    let num_vars = num_vars_for(n_permutations);
    let (chain_claims, claim_perms) = trace_chain_claims(ops, num_vars)?;
    if claim_perms != n_permutations {
        return Err(FiatShamirTranscriptError::ProofShape);
    }

    absorb_trace_public(channel, ops);

    let mle = BlockSpineMle::build_from_slot_state_ins(&slot_state_ins);
    let (main, r_prime) = prove_block_spine_unified(&mle, channel);
    let main_red = BlockSpineUnifiedReduction {
        r_prime: r_prime.clone(),
        s_in_dec_at_r: main.s_in_dec_at_r,
        s_out_dec_at_r: main.s_out_dec_at_r,
        state_dec_at_r: main.state_dec_at_r,
        state_at_r: main.state_at_r,
        s_out_lane_dec_at_r: main.s_out_lane_dec_at_r,
        state_lane_dec_at_r: main.state_lane_dec_at_r,
        beta: Block128::ZERO,
        gamma: Block128::ZERO,
    };
    let (shift, r_double_prime) = prove_block_spine_shift(&mle, &r_prime, &main_red, channel);
    let (chain, chain_red) = prove_linear_eval_prebound(
        &mle.state,
        &chain_claims,
        FS_TRANSCRIPT_LINEAR_RELATION_TAG,
        channel,
    );

    let state_claims = vec![
        EvalClaim {
            point: r_prime,
            value: main.state_at_r,
        },
        EvalClaim {
            point: r_double_prime.clone(),
            value: shift.state_at_r2,
        },
        EvalClaim {
            point: chain_red.point,
            value: chain_red.value,
        },
    ];
    let sin_claims = vec![EvalClaim {
        point: r_double_prime.clone(),
        value: shift.s_in_at_r2,
    }];
    let sout_claims = vec![EvalClaim {
        point: r_double_prime,
        value: shift.s_out_at_r2,
    }];
    let columns: [&[Block128]; 3] = [&mle.state, &mle.s_in, &mle.s_out];
    let claims_by_column: [&[EvalClaim]; 3] = [&state_claims, &sin_claims, &sout_claims];
    let (batch, reductions) = prove_multi_batch_eval(&columns, &claims_by_column, channel);
    let [state_red, sin_red, sout_red]: [BatchEvalReduction; 3] = reductions
        .try_into()
        .expect("multi-batch returns one reduction per column");

    Ok((
        FiatShamirTranscriptProofKillShot {
            kill_shot: BlockSpineKillShotProof { main, shift },
            chain,
            batch,
            n_ops: ops.len(),
            n_permutations,
            num_vars: mle.num_vars,
            live_slots: mle.live_slots,
        },
        FiatShamirTranscriptReductions {
            state: state_red,
            sin: sin_red,
            sout: sout_red,
        },
    ))
}

pub fn verify_fiat_shamir_transcript_killshot<T: FiatShamir<Block128>>(
    ops: &[FiatShamirTraceOp],
    proof: &FiatShamirTranscriptProofKillShot,
    channel: &mut T,
) -> Result<FiatShamirTranscriptReductions, FiatShamirTranscriptError> {
    let num_vars = num_vars_for(proof.n_permutations);
    let (chain_claims, n_permutations) = trace_chain_claims(ops, num_vars)?;
    if proof.n_ops != ops.len()
        || proof.n_permutations != n_permutations
        || proof.live_slots != n_permutations
        || proof.num_vars != num_vars
    {
        return Err(FiatShamirTranscriptError::ProofShape);
    }

    absorb_trace_public(channel, ops);

    let main_red = verify_block_spine_unified(
        &proof.kill_shot.main,
        proof.num_vars,
        proof.live_slots,
        channel,
    )
    .ok_or(FiatShamirTranscriptError::ProofRejected)?;
    let shift_red =
        verify_block_spine_shift(&proof.kill_shot.shift, &main_red, proof.num_vars, channel)
            .ok_or(FiatShamirTranscriptError::ProofRejected)?;
    let chain_red = verify_linear_eval_prebound(
        &proof.chain,
        &chain_claims,
        proof.num_vars,
        FS_TRANSCRIPT_LINEAR_RELATION_TAG,
        channel,
    )
    .ok_or(FiatShamirTranscriptError::ProofRejected)?;

    let state_claims = vec![
        EvalClaim {
            point: main_red.r_prime,
            value: main_red.state_at_r,
        },
        EvalClaim {
            point: shift_red.r_double_prime.clone(),
            value: shift_red.state_at_r2,
        },
        EvalClaim {
            point: chain_red.point,
            value: chain_red.value,
        },
    ];
    let sin_claims = vec![EvalClaim {
        point: shift_red.r_double_prime.clone(),
        value: shift_red.s_in_at_r2,
    }];
    let sout_claims = vec![EvalClaim {
        point: shift_red.r_double_prime,
        value: shift_red.s_out_at_r2,
    }];
    let claims_by_column: [&[EvalClaim]; 3] = [&state_claims, &sin_claims, &sout_claims];
    let reductions =
        verify_multi_batch_eval(&proof.batch, &claims_by_column, proof.num_vars, channel)
            .ok_or(FiatShamirTranscriptError::ProofRejected)?;
    let [state_red, sin_red, sout_red]: [BatchEvalReduction; 3] = reductions
        .try_into()
        .map_err(|_| FiatShamirTranscriptError::ProofRejected)?;

    Ok(FiatShamirTranscriptReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

pub fn prove_fiat_shamir_transcript_batch_killshot<T: FiatShamir<Block128>>(
    traces: &[Vec<FiatShamirTraceOp>],
    channel: &mut T,
) -> Result<
    (
        FiatShamirTranscriptBatchProofKillShot,
        FiatShamirTranscriptReductions,
    ),
    FiatShamirTranscriptError,
> {
    let slot_state_ins = evaluate_trace_batch_permutations(traces)?;
    let n_permutations = slot_state_ins.len();
    let num_vars = num_vars_for(n_permutations);
    let (chain_claims, n_ops, claim_perms) = trace_batch_chain_claims(traces, num_vars)?;
    if claim_perms != n_permutations {
        return Err(FiatShamirTranscriptError::ProofShape);
    }

    absorb_trace_batch_public(channel, traces);

    let mle = BlockSpineMle::build_from_slot_state_ins(&slot_state_ins);
    let (main, r_prime) = prove_block_spine_unified(&mle, channel);
    let main_red = BlockSpineUnifiedReduction {
        r_prime: r_prime.clone(),
        s_in_dec_at_r: main.s_in_dec_at_r,
        s_out_dec_at_r: main.s_out_dec_at_r,
        state_dec_at_r: main.state_dec_at_r,
        state_at_r: main.state_at_r,
        s_out_lane_dec_at_r: main.s_out_lane_dec_at_r,
        state_lane_dec_at_r: main.state_lane_dec_at_r,
        beta: Block128::ZERO,
        gamma: Block128::ZERO,
    };
    let (shift, r_double_prime) = prove_block_spine_shift(&mle, &r_prime, &main_red, channel);
    let (chain, chain_red) = prove_linear_eval_prebound(
        &mle.state,
        &chain_claims,
        FS_TRANSCRIPT_LINEAR_RELATION_TAG,
        channel,
    );

    let state_claims = vec![
        EvalClaim {
            point: r_prime,
            value: main.state_at_r,
        },
        EvalClaim {
            point: r_double_prime.clone(),
            value: shift.state_at_r2,
        },
        EvalClaim {
            point: chain_red.point,
            value: chain_red.value,
        },
    ];
    let sin_claims = vec![EvalClaim {
        point: r_double_prime.clone(),
        value: shift.s_in_at_r2,
    }];
    let sout_claims = vec![EvalClaim {
        point: r_double_prime,
        value: shift.s_out_at_r2,
    }];
    let columns: [&[Block128]; 3] = [&mle.state, &mle.s_in, &mle.s_out];
    let claims_by_column: [&[EvalClaim]; 3] = [&state_claims, &sin_claims, &sout_claims];
    let (batch, reductions) = prove_multi_batch_eval(&columns, &claims_by_column, channel);
    let [state_red, sin_red, sout_red]: [BatchEvalReduction; 3] = reductions
        .try_into()
        .expect("multi-batch returns one reduction per column");

    Ok((
        FiatShamirTranscriptBatchProofKillShot {
            kill_shot: BlockSpineKillShotProof { main, shift },
            chain,
            batch,
            n_traces: traces.len(),
            n_ops,
            n_permutations,
            num_vars: mle.num_vars,
            live_slots: mle.live_slots,
        },
        FiatShamirTranscriptReductions {
            state: state_red,
            sin: sin_red,
            sout: sout_red,
        },
    ))
}

pub fn verify_fiat_shamir_transcript_batch_killshot<T: FiatShamir<Block128>>(
    traces: &[Vec<FiatShamirTraceOp>],
    proof: &FiatShamirTranscriptBatchProofKillShot,
    channel: &mut T,
) -> Result<FiatShamirTranscriptReductions, FiatShamirTranscriptError> {
    if traces.is_empty() {
        return Err(FiatShamirTranscriptError::EmptyTrace);
    }
    let num_vars = num_vars_for(proof.n_permutations);
    let (chain_claims, n_ops, n_permutations) = trace_batch_chain_claims(traces, num_vars)?;
    if proof.n_traces != traces.len()
        || proof.n_ops != n_ops
        || proof.n_permutations != n_permutations
        || proof.live_slots != n_permutations
        || proof.num_vars != num_vars
    {
        return Err(FiatShamirTranscriptError::ProofShape);
    }

    absorb_trace_batch_public(channel, traces);

    let main_red = verify_block_spine_unified(
        &proof.kill_shot.main,
        proof.num_vars,
        proof.live_slots,
        channel,
    )
    .ok_or(FiatShamirTranscriptError::ProofRejected)?;
    let shift_red =
        verify_block_spine_shift(&proof.kill_shot.shift, &main_red, proof.num_vars, channel)
            .ok_or(FiatShamirTranscriptError::ProofRejected)?;
    let chain_red = verify_linear_eval_prebound(
        &proof.chain,
        &chain_claims,
        proof.num_vars,
        FS_TRANSCRIPT_LINEAR_RELATION_TAG,
        channel,
    )
    .ok_or(FiatShamirTranscriptError::ProofRejected)?;

    let state_claims = vec![
        EvalClaim {
            point: main_red.r_prime,
            value: main_red.state_at_r,
        },
        EvalClaim {
            point: shift_red.r_double_prime.clone(),
            value: shift_red.state_at_r2,
        },
        EvalClaim {
            point: chain_red.point,
            value: chain_red.value,
        },
    ];
    let sin_claims = vec![EvalClaim {
        point: shift_red.r_double_prime.clone(),
        value: shift_red.s_in_at_r2,
    }];
    let sout_claims = vec![EvalClaim {
        point: shift_red.r_double_prime,
        value: shift_red.s_out_at_r2,
    }];
    let claims_by_column: [&[EvalClaim]; 3] = [&state_claims, &sin_claims, &sout_claims];
    let reductions =
        verify_multi_batch_eval(&proof.batch, &claims_by_column, proof.num_vars, channel)
            .ok_or(FiatShamirTranscriptError::ProofRejected)?;
    let [state_red, sin_red, sout_red]: [BatchEvalReduction; 3] = reductions
        .try_into()
        .map_err(|_| FiatShamirTranscriptError::ProofRejected)?;

    Ok(FiatShamirTranscriptReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

pub fn discharge_fiat_shamir_transcript_reductions_native(
    ops: &[FiatShamirTraceOp],
    reductions: &FiatShamirTranscriptReductions,
) -> bool {
    let Ok(slot_state_ins) = evaluate_trace_permutations(ops) else {
        return false;
    };
    noid_gkr::block_spine::discharge_block_spine_batch_reductions_from_slot_state_ins_native(
        &slot_state_ins,
        &reductions.state,
        &reductions.sin,
        &reductions.sout,
    )
}

pub fn discharge_fiat_shamir_transcript_batch_reductions_native(
    traces: &[Vec<FiatShamirTraceOp>],
    reductions: &FiatShamirTranscriptReductions,
) -> bool {
    let Ok(slot_state_ins) = evaluate_trace_batch_permutations(traces) else {
        return false;
    };
    noid_gkr::block_spine::discharge_block_spine_batch_reductions_from_slot_state_ins_native(
        &slot_state_ins,
        &reductions.state,
        &reductions.sin,
        &reductions.sout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::verify_authorization_batch_native_with_traces;
    use noid_chain::{Block, BlockHeader};
    use noid_gkr::OwnerAuthWitness;
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret};
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    fn synthetic_trace() -> Vec<FiatShamirTraceOp> {
        let mut ch = Poseidon2bChannel::new();
        let mut ops = Vec::new();
        ch.absorb(Block128::from(1u128));
        ops.push(FiatShamirTraceOp::Absorb(Block128::from(1u128)));
        ch.absorb(Block128::from(2u128));
        ops.push(FiatShamirTraceOp::Absorb(Block128::from(2u128)));
        let a = ch.squeeze();
        ops.push(FiatShamirTraceOp::Squeeze(a));
        let b = ch.squeeze();
        ops.push(FiatShamirTraceOp::Squeeze(b));
        ch.absorb(Block128::from(3u128));
        ops.push(FiatShamirTraceOp::Absorb(Block128::from(3u128)));
        let c = ch.squeeze();
        ops.push(FiatShamirTraceOp::Squeeze(c));
        ops
    }

    fn auth_trace() -> Vec<FiatShamirTraceOp> {
        let secret = SpendSecret([0x73; 32]);
        let owner = derive_address(&secret);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 100,
            creation_id: 0,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 1007,
            amount: 97,
            owner: Address([0x11; 32]),
        };
        let body = TxBody {
            epoch_anchor: [0xA5; 32],
            fee: 3,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        };
        let tx = Transaction::new(body);
        let proof = noid_gkr::prove_wallet_authorization(&tx.body, OwnerAuthWitness::new(secret))
            .expect("wallet auth")
            .proof;
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [1u8; 32],
                tx_root: [2u8; 32],
                timestamp: 1,
                height: 1,
                miner_address: Address([0x33; 32]),
                nonce: 0,
                difficulty_target: [0xFF; 32],
                log_slots: 24,
                active_slot_count: 1,
                alloc_counter: 1,
            },
            transactions: vec![tx],
        };
        let (_, traces) =
            verify_authorization_batch_native_with_traces(&block, std::slice::from_ref(&proof))
                .expect("auth trace verifies");
        traces[0].transcript.clone()
    }

    #[test]
    fn fs_transcript_killshot_roundtrip_synthetic() {
        let ops = synthetic_trace();
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) =
            prove_fiat_shamir_transcript_killshot(&ops, &mut ch_p).expect("prove transcript");
        let mut ch_v = Poseidon2bChannel::new();
        let verified = verify_fiat_shamir_transcript_killshot(&ops, &proof, &mut ch_v)
            .expect("verify transcript");
        assert_eq!(verified, reductions);
        assert!(discharge_fiat_shamir_transcript_reductions_native(
            &ops, &verified
        ));
    }

    #[test]
    fn fs_transcript_killshot_rejects_squeeze_tamper() {
        let ops = synthetic_trace();
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) =
            prove_fiat_shamir_transcript_killshot(&ops, &mut ch_p).expect("prove transcript");
        let mut bad = ops.clone();
        if let FiatShamirTraceOp::Squeeze(value) = &mut bad[2] {
            *value += Block128::ONE;
        }
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_fiat_shamir_transcript_killshot(&bad, &proof, &mut ch_v).is_err());
    }

    #[test]
    fn fs_transcript_killshot_accepts_real_authorization_trace() {
        let ops = auth_trace();
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) =
            prove_fiat_shamir_transcript_killshot(&ops, &mut ch_p).expect("prove auth trace");
        let mut ch_v = Poseidon2bChannel::new();
        let verified = verify_fiat_shamir_transcript_killshot(&ops, &proof, &mut ch_v)
            .expect("verify auth trace");
        assert_eq!(verified, reductions);
        assert!(proof.byte_len() > 0);
        assert!(discharge_fiat_shamir_transcript_reductions_native(
            &ops, &verified
        ));
    }

    #[test]
    fn fs_transcript_batch_killshot_accepts_multiple_traces() {
        let traces = vec![synthetic_trace(), auth_trace()];
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) = prove_fiat_shamir_transcript_batch_killshot(&traces, &mut ch_p)
            .expect("prove transcript batch");
        let mut ch_v = Poseidon2bChannel::new();
        let verified = verify_fiat_shamir_transcript_batch_killshot(&traces, &proof, &mut ch_v)
            .expect("verify transcript batch");
        assert_eq!(verified, reductions);
        assert_eq!(proof.n_traces, 2);
        assert!(discharge_fiat_shamir_transcript_batch_reductions_native(
            &traces, &verified
        ));
    }

    #[test]
    fn fs_transcript_batch_killshot_rejects_one_trace_tamper() {
        let traces = vec![synthetic_trace(), auth_trace()];
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_fiat_shamir_transcript_batch_killshot(&traces, &mut ch_p)
            .expect("prove transcript batch");
        let mut bad = traces.clone();
        if let FiatShamirTraceOp::Squeeze(value) = &mut bad[1][0] {
            *value += Block128::ONE;
        } else {
            for op in &mut bad[1] {
                if let FiatShamirTraceOp::Squeeze(value) = op {
                    *value += Block128::ONE;
                    break;
                }
            }
        }
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_fiat_shamir_transcript_batch_killshot(&bad, &proof, &mut ch_v).is_err());
    }

    #[test]
    fn fs_transcript_batch_rejects_too_many_traces_before_proving() {
        let traces = vec![synthetic_trace(); FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH + 1];
        let mut ch = Poseidon2bChannel::new();
        let result = prove_fiat_shamir_transcript_batch_killshot(&traces, &mut ch);
        assert!(matches!(
            result,
            Err(FiatShamirTranscriptError::TooManyTraces)
        ));
    }

    #[test]
    fn fs_transcript_rejects_too_long_trace_before_proving() {
        let ops = vec![
            FiatShamirTraceOp::Absorb(Block128::ONE);
            FIAT_SHAMIR_TRANSCRIPT_MAX_OPS_PER_TRACE + 1
        ];
        let mut ch = Poseidon2bChannel::new();
        let result = prove_fiat_shamir_transcript_killshot(&ops, &mut ch);
        assert!(matches!(
            result,
            Err(FiatShamirTranscriptError::TraceTooLong)
        ));
    }
}
