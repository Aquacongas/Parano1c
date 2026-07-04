// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The batched Merkle path killshot in the trace.
//!
//! Trace twins of `noid_gkr::merkle_batch_killshot`:
//! [`verify_batched_merkle_killshot_trace`] ← `verify_batched_merkle_killshot`
//! and [`discharge_batched_merkle_trace`] ←
//! `discharge_batched_merkle_reductions_native`. One module serves all three
//! Merkle users of `verify_accepted_block_batch_components`: the tx-root
//! component (`MerkleCircuit::build()`, TAG_COMPRESS) and the exact-state
//! path batches (`TAG_EXSTNOD` / `TAG_RGDNODE`).
//!
//! ## Shape note (data-dependent structure)
//!
//! `directions` and `active_depth` are TRACE-STRUCTURE constants here: they
//! select the claim/term layout at build time, exactly as the native
//! verifier's data-dependent branches select it at run time. For the tx-root
//! tree at the frozen shape maxima this is genuinely structural (depth and
//! directions are functions of the padded tx index). For the exact-state
//! trie the directions/depths derive from slot keys and `log_slots`, i.e.
//! the R1CS matrix varies with block content — that violates the
//! fixed-shape requirement of the recursion (the previous-proof verifier
//! needs a protocol-constant matrix), and is resolved by the shape-freeze
//! pass: direction bits become witness selectors with canonical padding.
//! The per-instance soundness of THIS module is unaffected — the trace
//! checks everything the native verifier checks for the given statement.

use noid_core::{Block128, TowerField};
use noid_gkr::merkle_batch_killshot::{
    BatchedMerkleProofKillShot, MERKLE_CHAIN_LINEAR_RELATION_TAG, MERKLE_PIN_LANES,
};
use noid_gkr::merkle_circuit::{MerkleCircuit, MerklePathInputs, MAX_MERKLE_DEPTH};
use noid_poseidon2b::native::domain::capacity_iv;
use noid_poseidon2b::native::permutation::{MDS_FULL, N_ROUNDS, STATE_SIZE};

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
    alloc_block, const_block, flat_of, pin_zero, BatchEvalReductionTrace, FieldR1csBuilder,
    LinExpr, RawChannelTrace,
};

/// Trace twin of `MerklePathInputs`. Digest lanes are witness expressions;
/// `directions` / `active_depth` are trace structure (module docs). The
/// canonical zero padding beyond `active_depth` (native
/// `inputs_are_canonical`) is structural: those lanes are constants.
pub struct MerklePathInputsTrace {
    pub leaf: [LinExpr; 2],
    pub siblings: Vec<[LinExpr; 2]>,
    pub directions: Vec<bool>,
    pub expected_root: [LinExpr; 2],
    pub active_depth: usize,
}

impl MerklePathInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &MerklePathInputs) -> Self {
        assert!(
            native.active_depth > 0 && native.active_depth <= MAX_MERKLE_DEPTH,
            "path off the trace shape"
        );
        // Canonicity is structural: beyond active_depth the wires do not
        // exist — the padding lanes are literal zero constants.
        for level in native.active_depth..MAX_MERKLE_DEPTH {
            assert_eq!(
                native.siblings[level],
                [Block128::ZERO; 2],
                "non-canonical sibling padding"
            );
            assert!(!native.directions[level], "non-canonical direction padding");
        }
        Self {
            leaf: std::array::from_fn(|i| alloc_block(b, native.leaf[i])),
            siblings: (0..native.active_depth)
                .map(|l| std::array::from_fn(|i| alloc_block(b, native.siblings[l][i])))
                .collect(),
            directions: native.directions[..native.active_depth].to_vec(),
            expected_root: std::array::from_fn(|i| alloc_block(b, native.expected_root[i])),
            active_depth: native.active_depth,
        }
    }

    fn live_slots(&self) -> usize {
        MerkleCircuit::live_slots(self.active_depth)
    }
}

/// Trace twin of `BatchedMerkleProofKillShot`.
pub struct BatchedMerkleProofTrace {
    pub main: BlockSpineUnifiedProofTrace,
    pub shift: BlockSpineShiftProofTrace,
    pub chain: LinearEvalProofTrace,
    pub batch: MultiBatchEvalProofTrace,
    pub n_paths: usize,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl BatchedMerkleProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &BatchedMerkleProofKillShot,
        inputs: &[MerklePathInputsTrace],
    ) -> Self {
        let live_slots: usize = inputs.iter().map(MerklePathInputsTrace::live_slots).sum();
        let num_vars = noid_gkr::block_spine::num_vars_for(live_slots);
        assert_eq!(native.n_paths, inputs.len(), "proof off the trace shape");
        assert_eq!(native.live_slots, live_slots, "proof off the trace shape");
        assert_eq!(native.num_vars, num_vars, "proof off the trace shape");
        Self {
            main: BlockSpineUnifiedProofTrace::alloc(b, &native.kill_shot.main, num_vars),
            shift: BlockSpineShiftProofTrace::alloc(b, &native.kill_shot.shift, num_vars),
            chain: LinearEvalProofTrace::alloc(b, &native.chain, num_vars),
            batch: MultiBatchEvalProofTrace::alloc(b, &native.batch, num_vars, 3),
            n_paths: inputs.len(),
            num_vars,
            live_slots,
        }
    }
}

/// Trace twin of `absorb_public_batch` (Merkle).
fn absorb_public_batch_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    circuit: &MerkleCircuit,
    inputs: &[MerklePathInputsTrace],
) {
    ch.absorb_const_tower(b, inputs.len() as u128);
    ch.absorb_const_tower(b, circuit.node_tag.as_u64() as u128);
    for input in inputs {
        // absorb_public_path
        ch.absorb(b, &input.expected_root[0]);
        ch.absorb(b, &input.expected_root[1]);
        ch.absorb(b, &input.leaf[0]);
        ch.absorb(b, &input.leaf[1]);
        for level in 0..MAX_MERKLE_DEPTH {
            if level < input.active_depth {
                ch.absorb(b, &input.siblings[level][0]);
                ch.absorb(b, &input.siblings[level][1]);
                ch.absorb_const_tower(b, input.directions[level] as u128);
            } else {
                // Canonical zero padding — constants.
                ch.absorb_const_tower(b, 0);
                ch.absorb_const_tower(b, 0);
                ch.absorb_const_tower(b, 0);
            }
        }
        ch.absorb_const_tower(b, input.active_depth as u128);
    }
}

/// Trace twin of `append_path_chain_claims_at_offset` — same claim and term
/// order; the direction branches are decided by the structural constants.
fn append_path_chain_claims_trace(
    circuit: &MerkleCircuit,
    input: &MerklePathInputsTrace,
    slot_offset: usize,
    num_vars: usize,
    claims: &mut Vec<LinearEvalClaimTrace>,
) {
    let mds = |row: usize, col: usize| Block128::from(MDS_FULL[row][col]);
    let depth = input.active_depth;
    let [iv_hi, iv_lo] = capacity_iv(circuit.node_tag);
    let iv_const =
        |lane: usize| flat_of(mds(lane, 2) * iv_hi + mds(lane, 3) * iv_lo);
    let mds_pair = |lane: usize, pair: &[LinExpr; 2]| {
        pair[0]
            .scale(flat_of(mds(lane, 0)))
            .add(&pair[1].scale(flat_of(mds(lane, 1))))
    };
    let state_term = |slot: usize, round: usize, lane: usize, coeff: Block128| LinearEvalTermTrace {
        index: spine_point_index(num_vars, slot, round, lane),
        coeff,
    };

    for level in 0..depth {
        let perm_a_slot = slot_offset + level * 2;
        let perm_b_slot = perm_a_slot + 1;
        let current_is_right = input.directions[level];

        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_term(perm_a_slot, 0, lane, Block128::ONE)];
            let value = if current_is_right {
                mds_pair(lane, &input.siblings[level]).add_const(iv_const(lane))
            } else if level == 0 {
                mds_pair(lane, &input.leaf).add_const(iv_const(lane))
            } else {
                let prev_perm_b = perm_a_slot - 1;
                terms.push(state_term(prev_perm_b, N_ROUNDS, 0, mds(lane, 0)));
                terms.push(state_term(prev_perm_b, N_ROUNDS, 1, mds(lane, 1)));
                LinExpr::constant(iv_const(lane))
            };
            claims.push(LinearEvalClaimTrace { terms, value });
        }

        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_term(perm_b_slot, 0, lane, Block128::ONE)];
            for src_lane in 0..STATE_SIZE {
                terms.push(state_term(perm_a_slot, N_ROUNDS, src_lane, mds(lane, src_lane)));
            }
            let value = if current_is_right {
                if level == 0 {
                    mds_pair(lane, &input.leaf)
                } else {
                    let prev_perm_b = perm_a_slot - 1;
                    terms.push(state_term(prev_perm_b, N_ROUNDS, 0, mds(lane, 0)));
                    terms.push(state_term(prev_perm_b, N_ROUNDS, 1, mds(lane, 1)));
                    LinExpr::zero()
                }
            } else {
                mds_pair(lane, &input.siblings[level])
            };
            claims.push(LinearEvalClaimTrace { terms, value });
        }
    }

    let last_perm_b = slot_offset + (depth - 1) * 2 + 1;
    for lane in 0..MERKLE_PIN_LANES {
        claims.push(LinearEvalClaimTrace {
            terms: vec![state_term(last_perm_b, N_ROUNDS, lane, Block128::ONE)],
            value: input.expected_root[lane].clone(),
        });
    }
}

/// Trace twin of `verify_batched_merkle_killshot`.
pub fn verify_batched_merkle_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    circuit: &MerkleCircuit,
    proof: &BatchedMerkleProofTrace,
    inputs: &[MerklePathInputsTrace],
) -> [BatchEvalReductionTrace; 3] {
    assert!(!inputs.is_empty());
    assert_eq!(proof.n_paths, inputs.len());
    let live_slots: usize = inputs.iter().map(MerklePathInputsTrace::live_slots).sum();
    assert_eq!(proof.live_slots, live_slots);
    assert_eq!(
        proof.num_vars,
        noid_gkr::block_spine::num_vars_for(proof.live_slots)
    );

    absorb_public_batch_trace(b, ch, circuit, inputs);

    let main_red =
        verify_block_spine_unified_trace(b, ch, &proof.main, proof.num_vars, proof.live_slots);
    let shift_red = verify_block_spine_shift_trace(b, ch, &proof.shift, &main_red, proof.num_vars);

    let mut chain_claims = Vec::new();
    let mut slot_offset = 0usize;
    for input in inputs {
        append_path_chain_claims_trace(circuit, input, slot_offset, proof.num_vars, &mut chain_claims);
        slot_offset += input.live_slots();
    }
    let chain_red = verify_linear_eval_prebound_trace(
        b,
        ch,
        &proof.chain,
        &chain_claims,
        proof.num_vars,
        MERKLE_CHAIN_LINEAR_RELATION_TAG,
    );

    close_spine_family_batch(b, ch, &main_red, &shift_red, &chain_red, &proof.batch, proof.num_vars)
}

/// Trace twin of `discharge_batched_merkle_reductions_native`: replay the
/// live compression chains (`merkle_oracle::evaluate_merkle`'s live prefix)
/// through the accumulator and pin the derived roots and column values.
pub fn discharge_batched_merkle_trace(
    b: &mut FieldR1csBuilder,
    circuit: &MerkleCircuit,
    inputs: &[MerklePathInputsTrace],
    reductions: &[BatchEvalReductionTrace; 3],
) {
    assert!(!inputs.is_empty());
    let [iv_hi, iv_lo] = capacity_iv(circuit.node_tag);
    let live_slots: usize = inputs.iter().map(MerklePathInputsTrace::live_slots).sum();
    let mut acc = ColumnAccumulator::new(b, &reductions[0].point, live_slots);

    for input in inputs {
        // merkle_oracle::build_state_in for the live chain: per level PermA
        // absorbs the left digest over the IV, PermB XOR-absorbs the right
        // digest into PermA's output rate.
        let mut current = [input.leaf[0].clone(), input.leaf[1].clone()];
        for level in 0..input.active_depth {
            let sibling = &input.siblings[level];
            let (left, right) = if input.directions[level] {
                (sibling.clone(), current.clone())
            } else {
                (current.clone(), sibling.clone())
            };
            let perm_a_in: [LinExpr; STATE_SIZE] = [
                left[0].clone(),
                left[1].clone(),
                const_block(iv_hi),
                const_block(iv_lo),
            ];
            let a_out = acc.push_slot(b, &perm_a_in);
            let perm_b_in: [LinExpr; STATE_SIZE] = [
                a_out[0].add(&right[0]),
                a_out[1].add(&right[1]),
                a_out[2].clone(),
                a_out[3].clone(),
            ];
            let b_out = acc.push_slot(b, &perm_b_in);
            current = [b_out[0].clone(), b_out[1].clone()];
        }
        // `witness.derived_root != input.expected_root → false` → pins.
        pin_zero(b, &current[0].add(&input.expected_root[0]));
        pin_zero(b, &current[1].add(&input.expected_root[1]));
    }

    let (state_value, sin_value, sout_value) = acc.finish();
    pin_zero(b, &state_value.add(&reductions[0].value));
    pin_zero(b, &sin_value.add(&reductions[1].value));
    pin_zero(b, &sout_value.add(&reductions[2].value));
}

/// Full [K]+[D] Merkle slot (component twin of `verify_tx_root_component`
/// and of the exact-state path legs — the caller picks the circuit tag and
/// supplies the channel, since exact-state runs several killshots per slot).
pub fn build_batched_merkle_slot(
    b: &mut FieldR1csBuilder,
    circuit: &MerkleCircuit,
    proof: &BatchedMerkleProofKillShot,
    inputs: &[MerklePathInputs],
) -> Vec<MerklePathInputsTrace> {
    let inputs_t: Vec<MerklePathInputsTrace> = inputs
        .iter()
        .map(|i| MerklePathInputsTrace::alloc(b, i))
        .collect();
    let proof_t = BatchedMerkleProofTrace::alloc(b, proof, &inputs_t);
    let mut ch = RawChannelTrace::new();
    let reds = verify_batched_merkle_killshot_trace(b, &mut ch, circuit, &proof_t, &inputs_t);
    discharge_batched_merkle_trace(b, circuit, &inputs_t, &reds);
    inputs_t
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_gkr::merkle_batch_killshot::{
        discharge_batched_merkle_reductions_native, prove_batched_merkle_killshot,
        verify_batched_merkle_killshot,
    };
    use noid_gkr::merkle_oracle::compute_merkle_root_with_directions;
    use noid_poseidon2b::channel::Poseidon2bChannel;

    fn fixture(seed: u64, depth: usize, dir_mask: u32) -> MerklePathInputs {
        let mut s = seed as u128 | 1;
        let mut rnd = || {
            s = s.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(13);
            Block128::from(s)
        };
        let leaf = [rnd(), rnd()];
        let mut siblings = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
        let mut directions = [false; MAX_MERKLE_DEPTH];
        for level in 0..depth {
            siblings[level] = [rnd(), rnd()];
            directions[level] = (dir_mask >> level) & 1 == 1;
        }
        let circuit = MerkleCircuit::build();
        let expected_root = compute_merkle_root_with_directions(
            &circuit,
            leaf,
            &siblings[..depth],
            &directions,
            depth,
        );
        MerklePathInputs {
            leaf,
            siblings,
            directions,
            expected_root,
            active_depth: depth,
        }
    }

    struct Fixture {
        proof: BatchedMerkleProofKillShot,
        inputs: Vec<MerklePathInputs>,
    }

    fn make_fixture() -> Fixture {
        let circuit = MerkleCircuit::build();
        // Varied depths AND directions (exercises every claim branch).
        let inputs = vec![fixture(1, 3, 0b101), fixture(2, 1, 0b1), fixture(3, 5, 0b01010)];
        let mut ch = Poseidon2bChannel::new();
        let (proof, _) = prove_batched_merkle_killshot(&circuit, &inputs, &mut ch);
        Fixture { proof, inputs }
    }

    fn native_accepts(f: &Fixture) -> bool {
        let circuit = MerkleCircuit::build();
        let mut ch = Poseidon2bChannel::new();
        verify_batched_merkle_killshot(&circuit, &f.proof, &f.inputs, &mut ch)
            .map(|red| discharge_batched_merkle_reductions_native(&circuit, &f.inputs, &red))
            .unwrap_or(false)
    }

    fn trace_accepts(f: &Fixture) -> bool {
        let circuit = MerkleCircuit::build();
        let mut b = FieldR1csBuilder::new();
        let _ = build_batched_merkle_slot(&mut b, &circuit, &f.proof, &f.inputs);
        let (r1cs, z) = b.build();
        r1cs.satisfies(&z)
    }

    #[test]
    fn batched_merkle_trace_positive() {
        let f = make_fixture();
        assert!(native_accepts(&f), "native fixture broken");
        let circuit = MerkleCircuit::build();
        let mut b = FieldR1csBuilder::new();
        let _ = build_batched_merkle_slot(&mut b, &circuit, &f.proof, &f.inputs);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest merkle trace unsatisfiable");
        eprintln!(
            "batched merkle slot (3 paths, depths 3/1/5): {} useful rows (k_log = {})",
            r1cs.useful_rows, r1cs.k_log
        );
    }

    fn visit_proof_fields(p: &mut BatchedMerkleProofKillShot, f: &mut dyn FnMut(&mut Block128)) {
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
        for r in &mut p.chain.rounds {
            for e in &mut r.evals {
                f(e);
            }
        }
        f(&mut p.chain.b_final);
        for r in &mut p.batch.rounds {
            for e in &mut r.evals {
                f(e);
            }
        }
        for v in &mut p.batch.b_finals {
            f(v);
        }
    }

    /// Replay-completeness auto-mutator (proof side). 0 surviving mutants.
    #[test]
    fn batched_merkle_proof_mutator_kills_all() {
        let f = make_fixture();
        let mut n_fields = 0usize;
        {
            let mut c = f.proof.clone();
            visit_proof_fields(&mut c, &mut |_| n_fields += 1);
        }
        let stride: usize = std::env::var("NOID_TRACE_MUTATE_STRIDE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let mut survivors = Vec::new();
        for target in (0..n_fields).step_by(stride) {
            let mut bad_proof = f.proof.clone();
            let mut i = 0usize;
            visit_proof_fields(&mut bad_proof, &mut |v| {
                if i == target {
                    *v += Block128::ONE;
                }
                i += 1;
            });
            let bad = Fixture {
                proof: bad_proof,
                inputs: f.inputs.clone(),
            };
            assert!(!native_accepts(&bad), "native accepted proof mutant {target}");
            if trace_accepts(&bad) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving merkle proof mutants: {survivors:?} of {n_fields}"
        );
    }

    /// Statement/discharge mutator: every live digest lane of every path.
    #[test]
    fn batched_merkle_statement_mutator_kills_all() {
        let f = make_fixture();
        let mut survivors = Vec::new();
        let mut target_id = 0usize;
        for path in 0..f.inputs.len() {
            let depth = f.inputs[path].active_depth;
            for lane_slot in 0..(2 + 2 + depth * 2) {
                let mut bad_inputs = f.inputs.clone();
                let p = &mut bad_inputs[path];
                match lane_slot {
                    0 | 1 => p.leaf[lane_slot] += Block128::ONE,
                    2 | 3 => p.expected_root[lane_slot - 2] += Block128::ONE,
                    k => {
                        let k = k - 4;
                        p.siblings[k / 2][k % 2] += Block128::ONE;
                    }
                }
                let bad = Fixture {
                    proof: f.proof.clone(),
                    inputs: bad_inputs,
                };
                assert!(
                    !native_accepts(&bad),
                    "native accepted statement mutant {target_id}"
                );
                if trace_accepts(&bad) {
                    survivors.push(target_id);
                }
                target_id += 1;
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving merkle statement mutants: {survivors:?}"
        );
    }

    /// Cross-test "trace ⇔ native" on randomized honest/mutated cases.
    #[test]
    fn batched_merkle_native_trace_equivalence() {
        let cases: usize = std::env::var("NOID_TRACE_CROSS_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let mut seed = 0x3E5C_1E77u128;
        let mut next = |m: u128| {
            seed = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            (seed >> 16) % m
        };
        let f = make_fixture();
        let mut n_fields = 0usize;
        {
            let mut c = f.proof.clone();
            visit_proof_fields(&mut c, &mut |_| n_fields += 1);
        }
        for case in 0..cases {
            let case_f = if case % 2 == 0 {
                Fixture {
                    proof: f.proof.clone(),
                    inputs: f.inputs.clone(),
                }
            } else {
                let target = next(n_fields as u128) as usize;
                let mut bad_proof = f.proof.clone();
                let mut i = 0usize;
                visit_proof_fields(&mut bad_proof, &mut |v| {
                    if i == target {
                        *v += Block128::ONE;
                    }
                    i += 1;
                });
                Fixture {
                    proof: bad_proof,
                    inputs: f.inputs.clone(),
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
