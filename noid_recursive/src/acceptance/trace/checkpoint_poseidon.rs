// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The `checkpoint_poseidon` component in the trace.
//!
//! Trace twin of the header-hash killshot behind
//! `noid_recursive::checkpoint::verify_checkpoint_poseidon`:
//!
//! - [`verify_header_hash_killshot_padded_trace`] ←
//!   `noid_gkr::header_hash_killshot::verify_header_hash_killshot_padded`
//!   (+ its discharge).
//!
//! Scope note (no header consensus belongs in the O(1) history proof): the
//! Native `verify_checkpoint_poseidon` prepends `validate_shape` (the
//! `pow_fields == pow_header_fields(header)` recomputation from the header
//! struct). Header consensus and direct ten-lane accumulator continuity are
//! separate relations. This slot replays only the header killshot and its
//! discharge over `HeaderHashInputs`; the block slot pins those same wires to
//! the accepted claim and direct accumulator transition.

use noid_core::Block128;
use noid_gkr::header_hash_killshot::{
    HeaderHashInputs, HeaderHashProofKillShot, HEADER_HASH_BLOCK_PERMS, HEADER_HASH_FIELDS,
    HEADER_HASH_LINEAR_RELATION_TAG, HEADER_HASH_PERMS_PER_ITEM, HEADER_HASH_PIN_LANES,
    HEADER_HASH_POW_PERMS,
};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_BLOCKHDR, TAG_POWHDR};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use super::batch_eval::{
    verify_linear_eval_prebound_trace, LinearEvalClaimTrace, LinearEvalProofTrace,
    MultiBatchEvalProofTrace,
};
use super::block_spine::{
    close_spine_family_batch, sponge_chain_claims_trace, verify_block_spine_shift_trace,
    verify_block_spine_unified_trace, BlockSpineShiftProofTrace, BlockSpineUnifiedProofTrace,
    ColumnAccumulator,
};
use super::{
    alloc_block, const_block, pin_zero, BatchEvalReductionTrace, FieldR1csBuilder, LinExpr,
    RawChannelTrace,
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
            expected_block_id: std::array::from_fn(|i| alloc_block(b, native.expected_block_id[i])),
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
                    term.coeff = LinExpr::zero();
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
    assert_eq!(
        proof.live_slots,
        padded_headers * HEADER_HASH_PERMS_PER_ITEM
    );
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

    close_spine_family_batch(
        b,
        ch,
        &main_red,
        &shift_red,
        &chain_red,
        &proof.batch,
        proof.num_vars,
    )
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
// Full slot assembly
// ---------------------------------------------------------------------------

/// Build the complete header-hash checkpoint [K]+[D] slot and return its
/// statement wires for block-level bindings.
pub fn build_checkpoint_poseidon_slot(
    b: &mut FieldR1csBuilder,
    proof: &crate::checkpoint::CheckpointPoseidonProof,
    header_inputs: &[HeaderHashInputs],
    padded_blocks: usize,
) -> Vec<HeaderHashInputsTrace> {
    let header_inputs_t: Vec<HeaderHashInputsTrace> = header_inputs
        .iter()
        .map(|i| HeaderHashInputsTrace::alloc(b, i))
        .collect();
    build_checkpoint_poseidon_slot_with_inputs(b, proof, &header_inputs_t, padded_blocks);
    header_inputs_t
}

/// The killshot replays over CALLER-OWNED statement wires — the block
/// assembly shares one header-statement allocation between this slot, the
/// claim-hash pins and the direct accumulator transition.
pub fn build_checkpoint_poseidon_slot_with_inputs(
    b: &mut FieldR1csBuilder,
    proof: &crate::checkpoint::CheckpointPoseidonProof,
    header_inputs_t: &[HeaderHashInputsTrace],
    padded_blocks: usize,
) {
    assert_eq!(proof.n_blocks, header_inputs_t.len());

    let header_proof_t =
        HeaderHashProofTrace::alloc(b, &proof.header_hash, header_inputs_t.len(), padded_blocks);
    let mut ch_header = RawChannelTrace::new();
    let header_reds = verify_header_hash_killshot_padded_trace(
        b,
        &mut ch_header,
        &header_proof_t,
        header_inputs_t,
        padded_blocks,
    );
    discharge_header_hash_padded_trace(b, header_inputs_t, &header_reds, padded_blocks);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accepted_batch::AcceptedClaimBatchWitness;
    use crate::checkpoint::{prove_checkpoint_poseidon_padded, CheckpointPoseidonProof};
    use crate::pow_header::{header_hash_proof_inputs, HeaderWitness};
    use noid_chain::consensus::params::MAX_TARGET;
    use noid_core::TowerField;
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

    fn fixture_n(n: usize) -> AcceptedClaimBatchWitness {
        assert!(n > 0);
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
            prev_block_id = w.block_id;
            headers.push(w);
            claims.push(claim);
        }
        AcceptedClaimBatchWitness {
            headers,
            accepted_block_claims: claims,
        }
    }

    struct Fixture {
        proof: CheckpointPoseidonProof,
        header_inputs: Vec<noid_gkr::header_hash_killshot::HeaderHashInputs>,
        padded_blocks: usize,
    }

    fn fixture(n: usize, padded_blocks: usize) -> Fixture {
        let witness = fixture_n(n);
        let proof = prove_checkpoint_poseidon_padded(&witness, padded_blocks).unwrap();
        Fixture {
            header_inputs: header_hash_proof_inputs(&witness.headers),
            proof,
            padded_blocks,
        }
    }

    /// Killshot-level native acceptance (the trace's exact scope — the
    /// header-struct `validate_shape` / accumulator boundary checks are [B]).
    fn native_accepts(f: &Fixture) -> bool {
        let mut ch = Poseidon2bChannel::new();
        verify_header_hash_killshot_padded(
            &f.proof.header_hash,
            &f.header_inputs,
            f.padded_blocks,
            &mut ch,
        )
        .map(|red| {
            discharge_header_hash_reductions_native_padded(&f.header_inputs, &red, f.padded_blocks)
        })
        .unwrap_or(false)
    }

    fn trace_accepts(f: &Fixture) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = FieldR1csBuilder::new();
            let _ =
                build_checkpoint_poseidon_slot(&mut b, &f.proof, &f.header_inputs, f.padded_blocks);
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        }))
        .unwrap_or(false)
    }

    /// Positive: K=1 shape (the per-block production case) and a padded batch.
    #[test]
    fn checkpoint_poseidon_trace_positive() {
        for (n, padded) in [(1usize, 1usize), (2, 4)] {
            let f = fixture(n, padded);
            assert!(native_accepts(&f), "native fixture broken (n={n})");
            let mut b = FieldR1csBuilder::new();
            let _ =
                build_checkpoint_poseidon_slot(&mut b, &f.proof, &f.header_inputs, f.padded_blocks);
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
        let spines = [&mut p.header_hash.kill_shot];
        for ks in spines {
            for rp in &mut ks.main.round_polys {
                for c in &mut rp.coeffs_no_linear {
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
                for c in &mut rp.coeffs_no_linear {
                    f(c);
                }
            }
            f(&mut ks.shift.s_in_at_r2);
            f(&mut ks.shift.s_out_at_r2);
            f(&mut ks.shift.state_at_r2);
        }
        for chain in [&mut p.header_hash.chain] {
            for r in &mut chain.rounds {
                for e in &mut r.evals_at_1_2 {
                    f(e);
                }
            }
            f(&mut chain.b_final);
        }
        for batch in [&mut p.header_hash.batch] {
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
                padded_blocks: f.padded_blocks,
            };
            assert!(
                !native_accepts(&bad),
                "native accepted proof mutant {target}"
            );
            if trace_accepts(&bad) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving checkpoint proof mutants: {survivors:?} of {n_fields}"
        );
    }

    /// Statement-side auto-mutator: every header field and digest lane.
    #[test]
    fn checkpoint_poseidon_statement_mutator_kills_all() {
        let f = fixture(1, 1);
        let header_fields = HEADER_HASH_FIELDS + 4; // fields + 2 digests
        let mut survivors = Vec::new();

        for target in 0..header_fields {
            let mut bad_header = f.header_inputs.clone();
            if target < HEADER_HASH_FIELDS {
                bad_header[0].fields[target] += Block128::ONE;
            } else if target < HEADER_HASH_FIELDS + 2 {
                bad_header[0].expected_pow_digest[target - HEADER_HASH_FIELDS] += Block128::ONE;
            } else if target < header_fields {
                bad_header[0].expected_block_id[target - HEADER_HASH_FIELDS - 2] += Block128::ONE;
            }
            let bad = Fixture {
                proof: f.proof.clone(),
                header_inputs: bad_header,
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
                    padded_blocks: f.padded_blocks,
                }
            } else {
                Fixture {
                    proof: mutate_field(&f.proof, next(n_fields as u128) as usize),
                    header_inputs: f.header_inputs.clone(),
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
