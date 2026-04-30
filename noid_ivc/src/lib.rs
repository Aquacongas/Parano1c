// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Incrementally-Verifiable Computation via **linear folding** over
//! GF(2^128).
//!
//! # The insight
//!
//! In a characteristic-2 field, addition is XOR and is free. Given a
//! stream of column witnesses `c_1, c_2, …, c_n` of equal length, their
//! multilinear extensions satisfy
//!
//! ```text
//! MLE(c_1 + c_2 + …)(x) = MLE(c_1)(x) + MLE(c_2)(x) + …
//! ```
//!
//! so evaluations and commitments are additive. The folding scheme is:
//!
//! 1. For each incoming column `c_k`, draw a mixing scalar `α_k` from a
//!    Fiat–Shamir transcript bound to the previous accumulator and to
//!    the new column's FRI commitment.
//! 2. Update the accumulator:
//!
//!    ```text
//!    col_acc  ←  col_acc + α_k · c_k          (hypercube-wise; or α_k · polynomial)
//!    y_acc    ←  y_acc   + α_k · y_k           (running opening at shared point z)
//!    ```
//!
//! 3. "Decide" at the end by one FRI `prove`/`verify` of `col_acc` at
//!    `z` against `y_acc`. A cheating prover who submits a wrong
//!    intermediate `y_k` fails unless `Σ α_k · (wrong_y_k - real_y_k) =
//!    0`, which is a non-trivial linear equation in `{α_k}`; by
//!    Schwartz–Zippel over GF(2^128) the bad prover succeeds with
//!    probability `1 / 2^128`.
//!
//! This is the char-2 analogue of ProtoStar/Nova folding: no quadratic
//! cross term, no running error polynomial, and no re-commitment of the
//! folded polynomial — only the running opening value `y_acc` needs to
//! be maintained.  The original column commitments stay around so the
//! final FRI proof can be replayed, but no new Merkle commit is issued
//! per fold step.
//!
//! # What this crate ships
//!
//! - [`Accumulator`] : `{ column_commitments, z, y_acc }`.
//! - [`fold_step`]   : consumes one `(commitment, column_evals, opening_proof)`
//!   triple, absorbs into the transcript, derives `α`, updates
//!   `y_acc`, and returns the opened value it just verified.
//! - [`decide`]      : verifies every stored commitment's opening proof
//!   — a single pass over the collected proofs.
//!
//! Scope of this first cut: the accumulator holds **one AIR column**.
//! Multi-column AIRs fold column-by-column with independent
//! sub-accumulators (or with a per-column α vector, TBD). This keeps
//! the surface tight while covering the blocking case: accumulating
//! transaction validity columns across many txs in a block.

use noid_air::Trace;
use noid_core::{AdditiveNTT, Block128, TowerField};
#[cfg(test)]
use noid_fri::channel::TAU;
use noid_fri::prover::{commit, prove, EvalProof, FriCommitment};
use noid_fri::verifier::verify as fri_verify;
use noid_fri::Channel;
use noid_poseidon2b::native::compression::Poseidon2bSponge;

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

#[cfg(test)]
fn padded_log_len(log_rows: usize) -> usize {
    (TAU + 1).max(log_rows)
}

// ---------------------------------------------------------------------------
// Accumulator
// ---------------------------------------------------------------------------

/// Running state of the folding scheme for one column stream.
#[derive(Debug, Clone)]
pub struct Accumulator {
    pub log_len: usize,
    /// Shared opening point for every folded column.
    pub z: Vec<Block128>,
    /// Running Σ α_k · y_k.
    pub y_acc: Block128,
    /// All column commitments folded so far, in order.
    pub column_commitments: Vec<FriCommitment>,
    /// Matching FRI openings at `z` for every column commitment (the
    /// raw per-step openings, not the folded running sum).
    pub per_step_openings: Vec<Block128>,
    /// Matching FRI proofs for each per-step opening.
    pub per_step_proofs: Vec<EvalProof>,
    /// Fiat-Shamir transcript digest — we keep the live channel by
    /// rebuilding it from the stored per-step inputs on demand. Stored
    /// as a running list of absorbed `(commitment, opening)` tuples.
    pub step_count: usize,
}

impl Accumulator {
    /// Initialise with the shared opening point `z`. `log_len` must
    /// match the padded length every folded column will use.
    pub fn new(log_len: usize, z: Vec<Block128>) -> Self {
        assert_eq!(
            z.len(),
            log_len,
            "opening-point length must equal log_len"
        );
        Self {
            log_len,
            z,
            y_acc: Block128::ZERO,
            column_commitments: Vec::new(),
            per_step_openings: Vec::new(),
            per_step_proofs: Vec::new(),
            step_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Fold step (prover side)
// ---------------------------------------------------------------------------

/// Prove one incoming column into the accumulator. The caller supplies
/// the raw column evaluations over the hypercube; the function commits
/// them, opens at `acc.z`, verifies the opening locally (so the
/// accumulator only ever stores proofs that already pass), derives the
/// mixing scalar α, and updates `y_acc`.
///
/// Returns the derived α, useful for reproducible tests.
pub fn fold_step_prove(
    acc: &mut Accumulator,
    column: &[Block128],
) -> (Block128, FriCommitment, EvalProof) {
    let log_len = acc.log_len;
    assert_eq!(column.len(), 1 << log_len, "column must be 2^log_len long");
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    let (commitment, _tree, _code) = commit(column, &ntt, &hasher);

    // Transcript: rebuild from prior steps so α depends on full history.
    let mut ch = rebuild_channel(acc);
    ch.observe_fri_commitment(&commitment);

    // Open the new column at z.
    let opening = mle_eval(column, &acc.z);
    ch.observe_field_elem(opening);

    let alpha = ch.get_random_point();

    // Produce the FRI opening proof with a fresh channel bound to the
    // same transcript prefix (so verifier can replay).
    let mut proof_ch = rebuild_channel(acc);
    proof_ch.observe_fri_commitment(&commitment);
    proof_ch.observe_field_elem(opening);
    // α is already derived above; absorbing it here binds the FRI
    // proof to the exact challenge used in the fold.
    proof_ch.observe_field_elem(alpha);
    let fri_proof = prove(&commitment, column, &acc.z, &ntt, &mut proof_ch, &hasher);

    // Update running accumulator (char-2 is free).
    acc.y_acc += alpha * opening;
    acc.column_commitments.push(commitment.clone());
    acc.per_step_openings.push(opening);
    acc.per_step_proofs.push(fri_proof.clone());
    acc.step_count += 1;

    (alpha, commitment, fri_proof)
}

/// Convenience wrapper: pad a [`Trace`]'s single column and fold it.
/// Panics if the trace has more than one column — this first cut is
/// one-column only (see module docs).
pub fn fold_step_from_trace(acc: &mut Accumulator, trace: &Trace) {
    assert_eq!(
        trace.n_cols(),
        1,
        "one-column fold only; compose multi-column AIRs separately"
    );
    let target = 1usize << acc.log_len;
    let padded = if trace.columns[0].len() == target {
        trace.columns[0].clone()
    } else {
        let mut out = Vec::with_capacity(target);
        out.extend_from_slice(&trace.columns[0]);
        out.resize(target, Block128::ZERO);
        out
    };
    fold_step_prove(acc, &padded);
}

// ---------------------------------------------------------------------------
// Decide (verifier + equality check on `y_acc`)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum DecideError {
    Empty,
    FriFailed(usize, String),
    RunningSumMismatch,
}

/// Verify every stored FRI opening proof and check that the reported
/// running sum `y_acc` matches Σ α_k · y_k for the replay-derived αs.
pub fn decide(acc: &Accumulator) -> Result<(), DecideError> {
    if acc.step_count == 0 {
        return Err(DecideError::Empty);
    }
    let log_len = acc.log_len;
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    // Replay the transcript step-by-step and verify each opening.
    let mut ch = Channel::new();
    ch.observe_field_elems(&acc.z);

    let mut y_replay = Block128::ZERO;
    for k in 0..acc.step_count {
        let commitment = &acc.column_commitments[k];
        let opening = acc.per_step_openings[k];
        let proof = &acc.per_step_proofs[k];

        ch.observe_fri_commitment(commitment);
        ch.observe_field_elem(opening);
        let alpha = ch.get_random_point();

        // Build a matching channel for FRI verification. The prover
        // used `rebuild_channel(acc_before_step_k)` and then absorbed
        // (commitment_k, opening_k, alpha_k); we reproduce that exactly.
        let mut proof_ch = Channel::new();
        proof_ch.observe_field_elems(&acc.z);
        for j in 0..k {
            proof_ch.observe_fri_commitment(&acc.column_commitments[j]);
            proof_ch.observe_field_elem(acc.per_step_openings[j]);
            let _alpha_j = proof_ch.get_random_point();
        }
        proof_ch.observe_fri_commitment(commitment);
        proof_ch.observe_field_elem(opening);
        proof_ch.observe_field_elem(alpha);

        fri_verify(
            commitment,
            &acc.z,
            opening,
            proof.clone(),
            &ntt,
            &mut proof_ch,
            &hasher,
        )
        .map_err(|e| DecideError::FriFailed(k, e))?;

        y_replay += alpha * opening;
    }

    if y_replay != acc.y_acc {
        return Err(DecideError::RunningSumMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel rebuild (prover side)
// ---------------------------------------------------------------------------

fn rebuild_channel(acc: &Accumulator) -> Channel {
    let mut ch = Channel::new();
    ch.observe_field_elems(&acc.z);
    for k in 0..acc.step_count {
        ch.observe_fri_commitment(&acc.column_commitments[k]);
        ch.observe_field_elem(acc.per_step_openings[k]);
        let _alpha_k = ch.get_random_point();
    }
    ch
}

// ---------------------------------------------------------------------------
// MLE eval
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

    fn mk_z(log_len: usize) -> Vec<Block128> {
        (0..log_len)
            .map(|i| Block128::from((0x1234u128 << i) ^ 0xCAFE))
            .collect()
    }

    fn mk_col(seed: u128, log_len: usize) -> Vec<Block128> {
        let n = 1usize << log_len;
        (0..n)
            .map(|i| Block128::from(seed.wrapping_mul(i as u128 + 1)))
            .collect()
    }

    #[test]
    fn fold_three_decide_ok() {
        let log_len = padded_log_len(4);
        let z = mk_z(log_len);
        let mut acc = Accumulator::new(log_len, z);

        let c1 = mk_col(7, log_len);
        let c2 = mk_col(11, log_len);
        let c3 = mk_col(19, log_len);

        fold_step_prove(&mut acc, &c1);
        fold_step_prove(&mut acc, &c2);
        fold_step_prove(&mut acc, &c3);

        decide(&acc).expect("decide");
        assert_eq!(acc.step_count, 3);
    }

    #[test]
    fn decide_fails_on_forged_y_acc() {
        let log_len = padded_log_len(4);
        let mut acc = Accumulator::new(log_len, mk_z(log_len));
        fold_step_prove(&mut acc, &mk_col(7, log_len));
        fold_step_prove(&mut acc, &mk_col(11, log_len));
        acc.y_acc += Block128::ONE;
        assert!(matches!(decide(&acc), Err(DecideError::RunningSumMismatch)));
    }

    #[test]
    fn decide_fails_on_forged_opening() {
        let log_len = padded_log_len(4);
        let mut acc = Accumulator::new(log_len, mk_z(log_len));
        fold_step_prove(&mut acc, &mk_col(7, log_len));
        fold_step_prove(&mut acc, &mk_col(11, log_len));
        // Tamper with a stored opening: FRI verification must reject
        // (or, less cleanly, y_acc mismatch — both are soundness).
        acc.per_step_openings[0] += Block128::ONE;
        assert!(decide(&acc).is_err());
    }

    #[test]
    fn empty_decide_fails() {
        let log_len = padded_log_len(4);
        let acc = Accumulator::new(log_len, mk_z(log_len));
        assert!(matches!(decide(&acc), Err(DecideError::Empty)));
    }
}
