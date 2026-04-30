// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! STARK wrapper for the Paranoid transaction AIRs.
//!
//! Given an [`Air`] + [`Trace`] and a [`PublicInputs`] tuple (CRYPTO.md
//! §7), this crate produces a non-interactive STARK proof that the
//! trace satisfies every AIR constraint on the boolean hypercube.
//!
//! # Pipeline
//!
//! 1. FRI-commit every trace column at `log_len = max(TAU+1, log_rows)`
//!    (zero-padded; see [`padded_log_len`]).
//! 2. Absorb `PublicInputs` and every column root into one parent
//!    Fiat–Shamir channel.
//! 3. Draw a zero-check point `z ∈ F^{log_len}` and per-constraint
//!    batching scalars `β_j`. Run **one** zero-check sumcheck on
//!    `H(x) = eq(z, x) · Σ_j β_j · C_j(col_0(x), …)`.
//! 4. Open every column at the sumcheck's own final challenge point
//!    `r`. The verifier's terminal check is
//!    `eq(z, r) · Σ_j β_j · C_j(openings(r)) == sumcheck_final_claim`.
//!
//! This is the standard zero-check protocol: soundness is driven by
//! Schwartz–Zippel on the sumcheck itself, not by a spurious
//! point-evaluation of a non-linear constraint against column MLEs.
//! Per-variable degree of `H` is `1 + max_j deg(C_j)`, so round
//! polynomials carry that many evaluations.

use noid_air::{Air, Constraint, Trace};
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::channel::TAU;
use noid_fri::prover::{commit, prove, EvalProof, FriCommitment};
use noid_fri::verifier::verify as fri_verify;
use noid_fri::Channel;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_tx::PublicInputs;

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/// Round polynomial stored as its `D+1` evaluations at
/// `X = 0, 1, 2, …, D` where `D` is the per-variable degree of the
/// batched zero-check polynomial.
pub type RoundPoly = Vec<Block128>;

/// A STARK proof. One FRI commitment per column, one shared opening
/// point `r` (the sumcheck's final challenge), one FRI evaluation
/// proof per column at `r`, plus the batched zero-check sumcheck
/// transcript.
#[derive(Debug, Clone)]
pub struct StarkProof {
    pub log_rows: usize,
    pub column_commitments: Vec<FriCommitment>,
    pub column_openings: Vec<Block128>,
    pub column_proofs: Vec<EvalProof>,
    /// Batched zero-check sumcheck: one `RoundPoly` per variable
    /// (`log_len` total), each a length-`(D+1)` vector of field
    /// evaluations.
    pub zero_check_rounds: Vec<RoundPoly>,
}

// ---------------------------------------------------------------------------
// Opening-point size + padding
// ---------------------------------------------------------------------------

pub fn padded_log_len(log_rows: usize) -> usize {
    (TAU + 1).max(log_rows)
}

fn pad_column(column: &[Block128], target_log: usize) -> Vec<Block128> {
    let target = 1usize << target_log;
    if column.len() == target {
        return column.to_vec();
    }
    assert!(target > column.len());
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(column);
    out.resize(target, Block128::ZERO);
    out
}

// ---------------------------------------------------------------------------
// Public-input absorbing
// ---------------------------------------------------------------------------

fn absorb_digest_as_pair(channel: &mut Channel, digest: &[u8; 32]) {
    let hi = u128::from_le_bytes(digest[..16].try_into().unwrap());
    let lo = u128::from_le_bytes(digest[16..].try_into().unwrap());
    channel.observe_field_elem(Block128::from(hi));
    channel.observe_field_elem(Block128::from(lo));
}

fn absorb_public_inputs(channel: &mut Channel, pi: &PublicInputs) {
    absorb_digest_as_pair(channel, &pi.prev_state_root);
    absorb_digest_as_pair(channel, &pi.new_state_root);
    absorb_digest_as_pair(channel, &pi.nullifier_root);
    absorb_digest_as_pair(channel, &pi.tx_body_hash.0);
    channel.observe_field_elem(Block128::from(pi.fee));
}

// ---------------------------------------------------------------------------
// Zero-check sumcheck
// ---------------------------------------------------------------------------

/// Maximum per-variable degree of `eq · Σ β_j · C_j` given the AIR.
/// Each constraint `C_j` contributes its own per-variable degree; the
/// multilinear `eq(z, ·)` contributes +1. Round polynomials therefore
/// carry `max_c + 2` evaluations — enough to pin down a degree-`(max_c
/// + 1)` univariate exactly.
fn round_poly_degree(air: &dyn Air) -> usize {
    let max_c = air
        .constraints()
        .iter()
        .map(|c| c.degree())
        .max()
        .unwrap_or(1);
    max_c + 1
}

/// Lagrange interpolation of `p` at `target`, where `p[i]` is the
/// evaluation of a degree-`(p.len()-1)` polynomial at the integer point
/// `i`, with integers embedded as `Block128::from(i as u8)`.
fn lagrange_eval_at(p: &[Block128], target: Block128) -> Block128 {
    let d_plus_one = p.len();
    let mut acc = Block128::ZERO;
    for (k, pk) in p.iter().enumerate() {
        let xk = Block128::from(k as u8);
        let mut num = Block128::ONE;
        let mut den = Block128::ONE;
        for m in 0..d_plus_one {
            if m == k {
                continue;
            }
            let xm = Block128::from(m as u8);
            num *= target + xm;
            den *= xk + xm;
        }
        acc += *pk * num * den.invert();
    }
    acc
}

/// Fold the highest variable of a multilinear table at an arbitrary
/// field point `r`, in place.
fn fold_highest<F: TowerField>(table: &mut Vec<F>, r: F) {
    let half = table.len() / 2;
    for j in 0..half {
        let lo = table[j];
        let hi = table[j + half];
        table[j] = lo + r * (hi + lo);
    }
    table.truncate(half);
}

/// Partial evaluation of a multilinear table at a field point `s` on
/// its highest variable — returns a new table of length `half`.
fn partial_eval_highest(table: &[Block128], s: Block128) -> Vec<Block128> {
    let half = table.len() / 2;
    (0..half)
        .map(|j| table[j] + s * (table[j + half] + table[j]))
        .collect()
}

/// Evaluate the per-row composition `eq · Σ β_j · C_j` given partial
/// tables at some value `s` of the current round variable, accumulated
/// over the remaining `half` hypercube positions.
fn accumulate_sum(
    eq_at_s: &[Block128],
    col_tables_at_s: &[Vec<Block128>],
    constraints: &[Box<dyn Constraint>],
    betas: &[Block128],
) -> Block128 {
    let half = eq_at_s.len();
    let mut scratch: Vec<Block128> = Vec::new();
    let mut acc = Block128::ZERO;
    for j in 0..half {
        // Evaluate Σ_k β_k · C_k(col0[j], col1[j], ...).
        let mut composition = Block128::ZERO;
        for (k, c) in constraints.iter().enumerate() {
            let cols_used = c.columns();
            scratch.clear();
            for &idx in cols_used {
                scratch.push(col_tables_at_s[idx][j]);
            }
            composition += betas[k] * c.evaluate(&scratch);
        }
        acc += eq_at_s[j] * composition;
    }
    acc
}

/// Prover for the batched zero-check sumcheck. Returns the list of
/// round polynomials (one per variable, each of length `degree + 1`)
/// and the vector of challenge points `r = (r_0, …, r_{n-1})`.
fn prove_zero_check(
    cols: &[Vec<Block128>],
    constraints: &[Box<dyn Constraint>],
    betas: &[Block128],
    z: &[Block128],
    channel: &mut Channel,
    degree: usize,
) -> (Vec<RoundPoly>, Vec<Block128>) {
    let n = z.len();
    let n_points = degree + 1;

    // Folded tables, one per column plus one for eq(z, ·).
    let mut cur_cols: Vec<Vec<Block128>> = cols.to_vec();
    let mut cur_eq = noid_core::mle::eq::eq_ind_partial_eval(z);

    let mut round_polys: Vec<RoundPoly> = Vec::with_capacity(n);
    let mut challenges: Vec<Block128> = Vec::with_capacity(n);

    for _ in 0..n {
        // Build round polynomial evaluations at 0, 1, 2, …, degree.
        let mut evals = Vec::with_capacity(n_points);
        for s_idx in 0..n_points {
            let s = Block128::from(s_idx as u8);
            let eq_at_s = partial_eval_highest(&cur_eq, s);
            let cols_at_s: Vec<Vec<Block128>> = cur_cols
                .iter()
                .map(|c| partial_eval_highest(c, s))
                .collect();
            evals.push(accumulate_sum(&eq_at_s, &cols_at_s, constraints, betas));
        }

        channel.observe_field_elems(&evals);
        let r = channel.get_random_point();

        fold_highest(&mut cur_eq, r);
        for c in cur_cols.iter_mut() {
            fold_highest(c, r);
        }

        round_polys.push(evals);
        challenges.push(r);
    }

    (round_polys, challenges)
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ProveError {
    TraceRejectedByAir,
}

pub fn prove_air<A: Air>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
) -> Result<StarkProof, ProveError> {
    if !air.check(trace) {
        return Err(ProveError::TraceRejectedByAir);
    }
    Ok(prove_air_unchecked(air, trace, pi))
}

/// Prover variant that skips the native AIR self-check. Exposed for
/// soundness testing: a malicious prover must be caught by the
/// cryptographic layer (zero-check + FRI), not by the defense-in-depth
/// native pre-check.
#[doc(hidden)]
pub fn prove_air_unchecked<A: Air>(air: &A, trace: &Trace, pi: &PublicInputs) -> StarkProof {
    let log_rows = trace.log_rows;
    let log_len = padded_log_len(log_rows);
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    // --- Commit columns (parallel across columns) ---
    let (commitments, padded_columns): (Vec<FriCommitment>, Vec<Vec<Block128>>) = {
        use rayon::prelude::*;
        trace
            .columns
            .par_iter()
            .map(|col| {
                let padded = pad_column(col, log_len);
                let (commitment, _tree, _code) = commit(&padded, &ntt, &hasher);
                (commitment, padded)
            })
            .unzip()
    };

    // --- Parent transcript: PI + column roots ---
    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    for c in &commitments {
        channel.observe_fri_commitment(c);
    }

    // --- Zero-check point `z` and constraint-batching scalars `β_j` ---
    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    // --- Batched zero-check sumcheck ---
    let degree = round_poly_degree(air);
    let (zero_check_rounds, r) = prove_zero_check(
        &padded_columns,
        air.constraints(),
        &betas,
        &z,
        &mut channel,
        degree,
    );

    // --- Column openings at the sumcheck's final challenge point ---
    // The sumcheck folds the highest variable first, so
    // `challenges[k]` binds `x_{n-1-k}`. For FRI / MLE-eval calls that
    // treat `point[i]` as `x_i`, we reverse the challenge vector.
    let r_point: Vec<Block128> = r.iter().rev().cloned().collect();
    let (openings, proofs): (Vec<Block128>, Vec<EvalProof>) = {
        use rayon::prelude::*;
        padded_columns
            .par_iter()
            .enumerate()
            .map(|(i, col)| {
                let mut col_ch = Channel::new();
                absorb_public_inputs(&mut col_ch, pi);
                for c in &commitments {
                    col_ch.observe_fri_commitment(c);
                }
                col_ch.observe_field_elem(Block128::from(i as u128));
                let opening = mle_eval(col, &r_point);
                let proof = prove(&commitments[i], col, &r_point, &ntt, &mut col_ch, &hasher);
                (opening, proof)
            })
            .unzip()
    };

    StarkProof {
        log_rows,
        column_commitments: commitments,
        column_openings: openings,
        column_proofs: proofs,
        zero_check_rounds,
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum VerifyError {
    ShapeMismatch,
    FriFailed(String),
    ZeroCheckFailed,
    ConstraintViolated,
}

pub fn verify_air<A: Air>(
    air: &A,
    pi: &PublicInputs,
    proof: &StarkProof,
) -> Result<(), VerifyError> {
    if proof.log_rows != air.log_rows() {
        return Err(VerifyError::ShapeMismatch);
    }
    if proof.column_commitments.len() != air.n_columns()
        || proof.column_openings.len() != air.n_columns()
        || proof.column_proofs.len() != air.n_columns()
    {
        return Err(VerifyError::ShapeMismatch);
    }

    let log_len = padded_log_len(proof.log_rows);
    if proof.zero_check_rounds.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }
    let degree = round_poly_degree(air);
    let n_points = degree + 1;
    for rp in &proof.zero_check_rounds {
        if rp.len() != n_points {
            return Err(VerifyError::ShapeMismatch);
        }
    }

    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    // --- Replay parent transcript ---
    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    for c in &proof.column_commitments {
        channel.observe_fri_commitment(c);
    }
    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    // --- Replay zero-check sumcheck ---
    let mut claim = Block128::ZERO;
    let mut challenges: Vec<Block128> = Vec::with_capacity(log_len);
    for rp in &proof.zero_check_rounds {
        // p(0) + p(1) == claim
        let sum01 = rp[0] + rp[1];
        if sum01 != claim {
            return Err(VerifyError::ZeroCheckFailed);
        }
        channel.observe_field_elems(rp);
        let r_i = channel.get_random_point();
        claim = lagrange_eval_at(rp, r_i);
        challenges.push(r_i);
    }

    // --- Final-claim check against the column openings ---
    // Sumcheck binds x_{n-1} first, so the opening point used for
    // column MLEs is the reversed challenge vector.
    let r_point: Vec<Block128> = challenges.iter().rev().cloned().collect();
    let eq_zr = noid_core::mle::eq::eq_ind(&z, &r_point);
    let mut composition = Block128::ZERO;
    for (k, c) in air.constraints().iter().enumerate() {
        let cols_used = c.columns();
        let vals: Vec<Block128> = cols_used
            .iter()
            .map(|&j| proof.column_openings[j])
            .collect();
        composition += betas[k] * c.evaluate(&vals);
    }
    if eq_zr * composition != claim {
        return Err(VerifyError::ConstraintViolated);
    }

    // --- Verify FRI openings at the same reversed point (parallel) ---
    {
        use rayon::prelude::*;
        let results: Vec<Result<(), String>> = proof
            .column_commitments
            .par_iter()
            .zip(proof.column_openings.par_iter().zip(proof.column_proofs.par_iter()))
            .enumerate()
            .map(|(i, (commitment, (opening, fri_proof)))| {
                let mut col_ch = Channel::new();
                absorb_public_inputs(&mut col_ch, pi);
                for c in &proof.column_commitments {
                    col_ch.observe_fri_commitment(c);
                }
                col_ch.observe_field_elem(Block128::from(i as u128));
                fri_verify(
                    commitment,
                    &r_point,
                    *opening,
                    fri_proof.clone(),
                    &ntt,
                    &mut col_ch,
                    &hasher,
                )
            })
            .collect();
        for r in results {
            r.map_err(VerifyError::FriFailed)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// MLE eval helper
// ---------------------------------------------------------------------------

fn mle_eval(evals: &[Block128], point: &[Block128]) -> Block128 {
    let mut buf = evals.to_vec();
    for &r in point.iter().rev() {
        let half = buf.len() / 2;
        for i in 0..half {
            buf[i] = buf[i] + r * (buf[i + half] + buf[i]);
        }
        buf.truncate(half);
    }
    buf[0]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_air::{
        Air, BoolGate, CompositeAir, Constraint, LinearCombinationAir, Trace, TxValidityAir,
        XorLinearGate,
    };
    use noid_poseidon2b::primitives::TxBodyHash;
    use noid_tx::{TxInput, TxOutput};

    fn mk_pi() -> PublicInputs {
        PublicInputs {
            prev_state_root: [0x11; 32],
            new_state_root: [0x22; 32],
            nullifier_root: [0x33; 32],
            tx_body_hash: TxBodyHash([0x44; 32]),
            fee: 7,
        }
    }

    fn mk_body() -> noid_tx::TxBody {
        let mut input = TxInput::dummy();
        input.valid = true;
        let mut output = TxOutput::dummy();
        output.valid = true;
        noid_tx::TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            fee: 0,
            inputs: vec![input, TxInput::dummy()],
            outputs: vec![output, TxOutput::dummy()],
        }
    }

    // -------- Degree-3 constraint: col0 · col1 · col2 == 0 --------

    struct Deg3ProductGate {
        cols: [usize; 3],
    }
    impl Constraint for Deg3ProductGate {
        fn degree(&self) -> usize {
            3
        }
        fn columns(&self) -> &[usize] {
            &self.cols
        }
        fn evaluate(&self, cols: &[Block128]) -> Block128 {
            cols[0] * cols[1] * cols[2]
        }
    }

    // -------- Degree-4 constraint: (col0)^2 · (col1)^2 == 0 --------

    struct Deg4SquareGate {
        cols: [usize; 2],
    }
    impl Constraint for Deg4SquareGate {
        fn degree(&self) -> usize {
            4
        }
        fn columns(&self) -> &[usize] {
            &self.cols
        }
        fn evaluate(&self, cols: &[Block128]) -> Block128 {
            let a = cols[0] * cols[0];
            let b = cols[1] * cols[1];
            a * b
        }
    }

    // -------- Helpers --------

    fn zero_col(log_rows: usize) -> Vec<Block128> {
        vec![Block128::ZERO; 1 << log_rows]
    }
    fn bool_col(log_rows: usize, seed: u64) -> Vec<Block128> {
        (0..(1usize << log_rows))
            .map(|i| {
                let bit = ((seed.wrapping_mul(2654435761).wrapping_add(i as u64)) >> 7) & 1;
                if bit == 0 { Block128::ZERO } else { Block128::ONE }
            })
            .collect()
    }

    // =====================================================================
    // Honest-prover tests, one per degree class
    // =====================================================================

    #[test]
    fn honest_linear_degree_1() {
        let air = LinearCombinationAir::new(3, 4);
        let n = 1 << 4;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 7 + 1)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 11 + 3)).collect();
        let col2: Vec<Block128> = col0.iter().zip(col1.iter()).map(|(a, b)| *a + *b).collect();
        let trace = Trace::new(vec![col0, col1, col2]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_bool_degree_2() {
        // A real non-degenerate boolean witness for BoolGate (degree 2).
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_bool_all_random_degree_2() {
        // A random boolean witness — not all-zero — must verify.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let col = bool_col(log_rows, 0xdead_beef);
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_cubic_degree_3() {
        // col0 · col1 · col2 == 0 when at least one column is all-zero on
        // the hypercube. Use col2 = 0 as the "indicator" column.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(Deg3ProductGate {
            cols: [0, 1, 2],
        })];
        let air = CompositeAir::from_parts(log_rows, 3, constraints);
        let n = 1 << log_rows;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 13 + 5)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 17 + 9)).collect();
        let col2 = zero_col(log_rows);
        let trace = Trace::new(vec![col0, col1, col2]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_quartic_degree_4() {
        // (col0)^2 · (col1)^2 == 0 when col0 is all-zero on the hypercube.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(Deg4SquareGate { cols: [0, 1] })];
        let air = CompositeAir::from_parts(log_rows, 2, constraints);
        let col0 = zero_col(log_rows);
        let n = 1 << log_rows;
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 23 + 1)).collect();
        let trace = Trace::new(vec![col0, col1]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_mixed_degrees_composite() {
        // Composite AIR mixing degree-1 (XOR), degree-2 (Bool),
        // degree-3 (triple product with a zero column) in one proof.
        // Round-poly degree = max(1,2,3) + 1 = 4.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(0)),
            Box::new(XorLinearGate::new(vec![1, 2])),
            Box::new(Deg3ProductGate { cols: [3, 1, 2] }),
        ];
        // col0 boolean, col1 = col2 (satisfies XOR), col3 = 0 (satisfies triple product).
        let col0 = bool_col(log_rows, 0x1234);
        let n = 1 << log_rows;
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 5 + 2)).collect();
        let col2 = col1.clone();
        let col3 = zero_col(log_rows);
        let air = CompositeAir::from_parts(log_rows, 4, constraints);
        let trace = Trace::new(vec![col0, col1, col2, col3]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    // =====================================================================
    // Cryptographic soundness: malicious-prover tests
    // =====================================================================

    #[test]
    fn malicious_non_bool_witness_rejected() {
        // The prover tries to prove BoolGate on a non-boolean witness,
        // bypassing the native pre-check. The zero-check sumcheck
        // MUST reject it — this is the exact bug that was broken before.
        let air = TxValidityAir::new();
        let mut trace = TxValidityAir::build_trace(&mk_body());
        trace.columns[0][2] = Block128::from(3u128); // not 0 or 1
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(
            verify_air(&air, &pi, &proof).is_err(),
            "verifier must reject a non-boolean witness for BoolGate"
        );
    }

    #[test]
    fn malicious_non_bool_random_rejected() {
        // Same idea, but the whole column is random (non-boolean).
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let n = 1 << log_rows;
        let bad_col: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 7 + 3)).collect();
        let trace = Trace::new(vec![bad_col]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn malicious_linear_imbalance_rejected() {
        // XorLinearGate: Σ col_i != 0 somewhere on the hypercube.
        let air = LinearCombinationAir::new(2, 4);
        let n = 1 << 4;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        // col1 is NOT col0, so col0 + col1 != 0 almost everywhere.
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 2 + 5)).collect();
        let trace = Trace::new(vec![col0, col1]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn malicious_cubic_violation_rejected() {
        // Degree-3 constraint violated on the hypercube.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(Deg3ProductGate {
            cols: [0, 1, 2],
        })];
        let air = CompositeAir::from_parts(log_rows, 3, constraints);
        let n = 1 << log_rows;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 2)).collect();
        let col2: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 3)).collect();
        let trace = Trace::new(vec![col0, col1, col2]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn malicious_quartic_violation_rejected() {
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(Deg4SquareGate { cols: [0, 1] })];
        let air = CompositeAir::from_parts(log_rows, 2, constraints);
        let n = 1 << log_rows;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 2)).collect();
        let trace = Trace::new(vec![col0, col1]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn malicious_one_row_violation_rejected() {
        // Even a *single* row violation must be caught — this is the
        // whole point of zero-check (it commits to every row via eq).
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let mut col = vec![Block128::ZERO; 1 << log_rows];
        col[5] = Block128::from(2u128); // one bad row among zeros
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    // =====================================================================
    // Tamper / shape tests
    // =====================================================================

    #[test]
    fn tampered_opening_rejected() {
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.column_openings[0] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn tampered_round_poly_rejected() {
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.zero_check_rounds[0][0] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn wrong_pi_rejected() {
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        let mut bad = pi;
        bad.fee = pi.fee + 1;
        assert!(verify_air(&air, &bad, &proof).is_err());
    }

    #[test]
    fn bad_trace_rejected_in_native_check() {
        let air = TxValidityAir::new();
        let mut trace: Trace = TxValidityAir::build_trace(&mk_body());
        trace.columns[0][0] = Block128::from(5u128);
        assert!(prove_air(&air, &trace, &mk_pi()).is_err());
    }

    #[test]
    fn round_poly_shape_matches_air_degree() {
        // Sanity: round polys in the proof must have length
        // `max_constraint_degree + 2`, independent of AIR.
        for (air_deg, air) in [
            (1usize, {
                let c: Vec<Box<dyn Constraint>> = vec![Box::new(XorLinearGate::new(vec![0, 1]))];
                CompositeAir::from_parts(4, 2, c)
            }),
            (2usize, {
                let c: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
                CompositeAir::from_parts(4, 1, c)
            }),
            (3usize, {
                let c: Vec<Box<dyn Constraint>> = vec![Box::new(Deg3ProductGate {
                    cols: [0, 1, 2],
                })];
                CompositeAir::from_parts(4, 3, c)
            }),
            (4usize, {
                let c: Vec<Box<dyn Constraint>> =
                    vec![Box::new(Deg4SquareGate { cols: [0, 1] })];
                CompositeAir::from_parts(4, 2, c)
            }),
        ] {
            let n_cols = air.n_columns();
            let cols: Vec<Vec<Block128>> = (0..n_cols).map(|_| zero_col(4)).collect();
            let trace = Trace::new(cols);
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            let expected_len = air_deg + 2;
            for rp in &proof.zero_check_rounds {
                assert_eq!(
                    rp.len(),
                    expected_len,
                    "round poly must carry deg+2 evaluations for air_deg={air_deg}"
                );
            }
            verify_air(&air, &pi, &proof).expect("verify");
        }
    }

    // =====================================================================
    // Unit tests for internal helpers (Lagrange / degree)
    // =====================================================================

    #[test]
    fn lagrange_eval_interpolates_known_polynomial() {
        // Build p(X) = 3 + 5X + 7X^2 + 11X^3 (coeffs in Block128).
        let a = [
            Block128::from(3u8),
            Block128::from(5u8),
            Block128::from(7u8),
            Block128::from(11u8),
        ];
        let pt = |x: Block128| {
            a[0] + x * (a[1] + x * (a[2] + x * a[3]))
        };
        let evals: Vec<Block128> = (0..4)
            .map(|i| pt(Block128::from(i as u8)))
            .collect();
        for target_i in 0..8u8 {
            let target = Block128::from(target_i);
            assert_eq!(lagrange_eval_at(&evals, target), pt(target));
        }
        // At a random-looking field point too.
        let target = Block128::from(0xabcdef0123456789u128);
        assert_eq!(lagrange_eval_at(&evals, target), pt(target));
    }

    #[test]
    fn lagrange_eval_degree_1_and_5() {
        // Degree 1.
        let p1 = |x: Block128| Block128::from(2u8) + x * Block128::from(3u8);
        let e1: Vec<Block128> = (0..2).map(|i| p1(Block128::from(i as u8))).collect();
        assert_eq!(
            lagrange_eval_at(&e1, Block128::from(7u8)),
            p1(Block128::from(7u8))
        );
        // Degree 5.
        let a = [
            Block128::from(1u8),
            Block128::from(2u8),
            Block128::from(3u8),
            Block128::from(5u8),
            Block128::from(8u8),
            Block128::from(13u8),
        ];
        let p5 = |x: Block128| {
            a[0] + x * (a[1] + x * (a[2] + x * (a[3] + x * (a[4] + x * a[5]))))
        };
        let e5: Vec<Block128> = (0..6).map(|i| p5(Block128::from(i as u8))).collect();
        for target_i in 0..12u8 {
            let t = Block128::from(target_i);
            assert_eq!(lagrange_eval_at(&e5, t), p5(t));
        }
    }

    #[test]
    fn round_poly_degree_matches_max_constraint() {
        let c1: Vec<Box<dyn Constraint>> = vec![Box::new(XorLinearGate::new(vec![0, 1]))];
        let air1 = CompositeAir::from_parts(4, 2, c1);
        assert_eq!(round_poly_degree(&air1), 2); // 1 + 1

        let c2: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air2 = CompositeAir::from_parts(4, 1, c2);
        assert_eq!(round_poly_degree(&air2), 3); // 2 + 1

        let c3: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(0)),
            Box::new(Deg3ProductGate { cols: [0, 1, 2] }),
            Box::new(Deg4SquareGate { cols: [0, 1] }),
        ];
        let air3 = CompositeAir::from_parts(4, 3, c3);
        assert_eq!(round_poly_degree(&air3), 5); // max(2,3,4) + 1
    }

    #[test]
    fn no_degree_skipping_anywhere() {
        // Defensive: make sure the verifier never silently accepts a
        // degree > 1 constraint just because it "doesn't run sumcheck on
        // it". If a quadratic gate is present, the proof must carry
        // round polys of length >= 4, and the verifier must enforce
        // that. We assert the shape requirement here too.
        let c: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air = CompositeAir::from_parts(4, 1, c);
        let trace = Trace::new(vec![zero_col(4)]);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        // Shape-check: round polys must carry deg+2 = 4 evals.
        assert!(proof.zero_check_rounds.iter().all(|r| r.len() == 4));
        // Shrink a round poly — verifier must complain about shape, not
        // silently ignore the higher-degree term.
        proof.zero_check_rounds[0].pop();
        assert!(matches!(
            verify_air(&air, &pi, &proof),
            Err(VerifyError::ShapeMismatch)
        ));
    }
}
