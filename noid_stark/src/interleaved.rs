// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop)]

//! FRI-Binius interleaved PCS integration for the STARK.
//!
//! Replaces per-column FRI commitments with a single interleaved Merkle
//! tree. All columns (AIR + boundary slices) are committed together;
//! openings happen via a mixed-point sumcheck + single FRI proof.
//!
//! The zero-check sumcheck and constraint composition logic are unchanged
//! from `lib.rs`; only the commitment and opening phases differ.

use noid_air::Air;
use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::hasher::Blake3Hasher;
use noid_fri::Channel;
use noid_fri_binius::{
    absorb_cap, interleaved_commit, prove_mixed_opening, verify_mixed_opening, EvalClaim,
    InterleavedCommitment, MixedOpeningProof,
};
use noid_tx::PublicInputs;
use rayon::prelude::*;

use crate::{
    absorb_public_inputs, lagrange_eval_at, mle_eval, padded_log_len, round_poly_degree, RoundPoly,
    SliceClaim, VerifyError,
};

// ---------------------------------------------------------------------------
// Proof structure (replaces StarkProof for the interleaved path)
// ---------------------------------------------------------------------------

/// STARK proof using the FRI-Binius interleaved PCS.
///
/// Smaller and faster than the per-column approach: one Merkle cap
/// replaces N column roots, and one mixed opening proof replaces the
/// batched FRI.
#[derive(Debug, Clone)]
pub struct InterleavedStarkProof {
    pub log_rows: usize,
    /// Single interleaved commitment for ALL columns (AIR + slices).
    pub commitment: InterleavedCommitment,
    /// Per-column base openings e_i = MLE_i(r_point) at the zero-check's
    /// challenge point (AIR columns only; slices open at r_B_low).
    pub base_openings: Vec<Block128>,
    /// Batched zero-check sumcheck rounds.
    pub zero_check_rounds: Vec<RoundPoly>,
    /// VSHIFT ladders for each rotated column.
    pub shift_partials: Vec<Vec<Block128>>,
    /// Multipoint sumcheck rounds (base + ladder + slice claims -> r'').
    pub multipoint_rounds: Vec<RoundPoly>,
    /// Mixed opening proof: opens all columns at r'' (primary) with
    /// slice claims as secondary eval points.
    pub mixed_opening: MixedOpeningProof,
    /// Stage 0 MLE Splitting: claimed values of boundary-slice columns
    /// at their respective GKR reduction points (r_B_low).
    pub slice_claimed_values: Vec<Block128>,
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// Prove a STARK using the FRI-Binius interleaved PCS.
///
/// Same logic as `prove_air_with_slices` but commits all columns into
/// one interleaved Merkle tree and opens via mixed-point FRI-Binius.
///
/// If `pre_committed` is `Some`, reuses the pre-computed commitment and
/// prover state (avoids re-running NTT + tree build for all columns).
#[allow(clippy::too_many_arguments)]
pub fn prove_air_interleaved<A: Air + ?Sized>(
    air: &A,
    padded_columns: &[Vec<Block128>],
    pi: &PublicInputs,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    log_len: usize,
    pre_committed: Option<(
        InterleavedCommitment,
        noid_fri_binius::InterleavedProverState,
    )>,
) -> InterleavedStarkProof {
    let log_rows = air.log_rows();
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Blake3Hasher::new();

    let n_air_cols = air.n_columns();

    // =========================================================================
    // Stage 1: Interleaved commitment (single Merkle tree for ALL columns)
    // =========================================================================
    let (commitment, prover_state) = match pre_committed {
        Some(pre) => pre,
        None => {
            let col_refs: Vec<&[Block128]> = padded_columns.iter().map(|c| c.as_slice()).collect();
            interleaved_commit(&col_refs, &ntt, &hasher)
        }
    };

    // =========================================================================
    // Stage 2: Fiat-Shamir channel setup
    // =========================================================================
    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    absorb_cap(&mut channel, &commitment.cap);
    if !extra_transcript.is_empty() {
        channel.observe_field_elems(extra_transcript);
    }

    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    // =========================================================================
    // Stage 3: Zero-check sumcheck (same as non-interleaved path)
    // =========================================================================
    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    assert!(
        shifted_indices.is_empty() || log_rows == padded_log_len(log_rows),
        "VSHIFT requires log_rows >= TAU+1"
    );
    let mut shifted_slot: Vec<Option<usize>> = vec![None; n_air_cols];
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        shifted_slot[col_id] = Some(slot);
    }
    let rotated_columns: Vec<Vec<Block128>> = shifted_indices
        .iter()
        .map(|&col_id| crate::vshift::cyclic_rotate_left(&padded_columns[col_id]))
        .collect();
    let mut sumcheck_cols: Vec<Vec<Block128>> =
        Vec::with_capacity(n_air_cols + rotated_columns.len());
    sumcheck_cols.extend_from_slice(&padded_columns[..n_air_cols]);
    sumcheck_cols.extend(rotated_columns);

    let degree = round_poly_degree(air);
    let (zero_check_rounds, r) = crate::prove_zero_check(
        &sumcheck_cols,
        air.constraints(),
        &betas,
        &z,
        &mut channel,
        degree,
        &shifted_slot,
        n_air_cols,
    );

    let r_point: Vec<Block128> = r.iter().rev().cloned().collect();

    // =========================================================================
    // Stage 4: Base openings (AIR columns only at r_point)
    // =========================================================================
    let base_openings: Vec<Block128> = padded_columns[..n_air_cols]
        .par_iter()
        .map(|col| mle_eval(col, &r_point))
        .collect();
    channel.observe_field_elems(&base_openings);

    // =========================================================================
    // Stage 5: VSHIFT ladder partials
    // =========================================================================
    let partials_per_slot: Vec<Vec<Block128>> = shifted_indices
        .par_iter()
        .map(|&col_id| crate::vshift::ladder_partials(&padded_columns[col_id], &r_point))
        .collect();
    for (slot, partials) in partials_per_slot.iter().enumerate() {
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
    }

    // Absorb slice claimed values.
    let slice_values: Vec<Block128> = slice_claims.iter().map(|sc| sc.value).collect();
    channel.observe_field_elems(&slice_values);

    // =========================================================================
    // Stage 6: Multipoint sumcheck (base + ladder + slices -> common r'')
    // =========================================================================
    let s_count = shifted_indices.len();
    let n_slices = slice_claims.len();
    let gammas: Vec<Block128> = (0..s_count).map(|_| channel.get_random_point()).collect();

    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();

    let total_weights = n_air_cols + s_count + n_slices;
    let lambdas: Vec<Block128> = {
        let mut v = Vec::with_capacity(total_weights);
        let mut cur = Block128::ONE;
        for _ in 0..total_weights {
            v.push(cur);
            cur *= beta;
        }
        v
    };

    // Target = base + ladder + slice claims.
    let mut target = Block128::ZERO;
    for i in 0..n_air_cols {
        target += lambdas[i] * base_openings[i];
    }
    for (slot, partials) in partials_per_slot.iter().enumerate() {
        let t_s = crate::ladder_batch::target_claim(gammas[slot], partials);
        target += lambdas[n_air_cols + slot] * t_s;
    }
    for (i, sc) in slice_claims.iter().enumerate() {
        target += lambdas[n_air_cols + s_count + i] * sc.value;
    }

    // Fused base pair: (eq(r_point, x), sum_i lambda_i * AIR_col_i(x)).
    let eq_base = eq_ind_partial_eval(&r_point);
    let hyper_len = 1usize << log_len;
    let combined_base_b: Vec<Block128> = (0..hyper_len)
        .into_par_iter()
        .map(|j| {
            let mut acc = Block128::ZERO;
            for i in 0..n_air_cols {
                acc += lambdas[i] * padded_columns[i][j];
            }
            acc
        })
        .collect();

    let weight_trails = if s_count > 0 {
        Some(crate::ladder_batch::WeightTrails::new(&r_point))
    } else {
        None
    };
    let ladder_pairs_a: Vec<Vec<Block128>> = (0..s_count)
        .into_par_iter()
        .map(|slot| {
            let trails = weight_trails
                .as_ref()
                .expect("trails present when s_count > 0");
            let mut w = crate::ladder_batch::build_weight_table_from_trails(gammas[slot], trails);
            let eta = lambdas[n_air_cols + slot];
            for v in w.iter_mut() {
                *v *= eta;
            }
            w
        })
        .collect();
    let ladder_pairs_b: Vec<&[Block128]> = (0..s_count)
        .map(|slot| padded_columns[shifted_indices[slot]].as_slice())
        .collect();

    // Slice-claim pairs.
    let slice_pairs_a: Vec<Vec<Block128>> = (0..n_slices)
        .into_par_iter()
        .map(|i| {
            let lam = lambdas[n_air_cols + s_count + i];
            let eq_s = eq_ind_partial_eval(&slice_claims[i].eval_point);
            eq_s.into_iter().map(|v| v * lam).collect()
        })
        .collect();
    let slice_pairs_b: Vec<&[Block128]> = (0..n_slices)
        .map(|i| padded_columns[slice_claims[i].col_index].as_slice())
        .collect();

    // Assemble all pairs: [fused_base, ladder_0..s, slice_0..n_slices]
    let mut pairs_a: Vec<Vec<Block128>> = Vec::with_capacity(1 + s_count + n_slices);
    pairs_a.push(eq_base);
    pairs_a.extend(ladder_pairs_a);
    pairs_a.extend(slice_pairs_a);
    let mut pairs_b: Vec<&[Block128]> = Vec::with_capacity(1 + s_count + n_slices);
    pairs_b.push(combined_base_b.as_slice());
    pairs_b.extend(ladder_pairs_b);
    pairs_b.extend(slice_pairs_b);

    let (multipoint_rounds, challenges) =
        crate::multipoint_batch::prove_multipoint_sumcheck(pairs_a, pairs_b, target, &mut channel);
    let r_pp: Vec<Block128> = challenges.iter().rev().cloned().collect();
    debug_assert_eq!(r_pp.len(), log_len);

    // =========================================================================
    // Stage 7: FRI-Binius mixed opening at r'' (primary) + slice points (secondary)
    // =========================================================================
    // Build secondary claims: slice columns opened at their own points.
    let secondary_claims: Vec<EvalClaim> = slice_claims
        .iter()
        .map(|sc| EvalClaim {
            col_index: sc.col_index,
            eval_point: sc.eval_point.clone(),
            value: sc.value,
        })
        .collect();

    let mixed_opening = prove_mixed_opening(
        &prover_state,
        &r_pp,
        &secondary_claims,
        &ntt,
        &mut channel,
        &hasher,
    );

    InterleavedStarkProof {
        log_rows,
        commitment,
        base_openings,
        zero_check_rounds,
        shift_partials: partials_per_slot,
        multipoint_rounds,
        mixed_opening,
        slice_claimed_values: slice_values,
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify an [`InterleavedStarkProof`].
pub fn verify_air_interleaved<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &InterleavedStarkProof,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
) -> Result<(), VerifyError> {
    let n_air_cols = air.n_columns();
    let n_slices = slice_claims.len();
    let n_total = n_air_cols + n_slices;

    if proof.log_rows != air.log_rows() {
        return Err(VerifyError::ShapeMismatch);
    }
    if proof.commitment.n_cols != n_total {
        return Err(VerifyError::ShapeMismatch);
    }
    if proof.base_openings.len() != n_air_cols {
        return Err(VerifyError::ShapeMismatch);
    }

    let log_len = padded_log_len(proof.log_rows);
    if proof.commitment.log_rows != log_len {
        return Err(VerifyError::ShapeMismatch);
    }
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
    if proof.multipoint_rounds.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }
    for rp in &proof.multipoint_rounds {
        if rp.len() != crate::multipoint_batch::MULTIPOINT_ROUND_POINTS {
            return Err(VerifyError::ShapeMismatch);
        }
    }

    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Blake3Hasher::new();

    // --- Replay parent transcript ---
    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    absorb_cap(&mut channel, &proof.commitment.cap);
    if !extra_transcript.is_empty() {
        channel.observe_field_elems(extra_transcript);
    }
    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    // --- Zero-check replay ---
    let mut claim = Block128::ZERO;
    let mut challenges: Vec<Block128> = Vec::with_capacity(log_len);
    for rp in &proof.zero_check_rounds {
        let sum01 = rp[0] + rp[1];
        if sum01 != claim {
            return Err(VerifyError::ZeroCheckFailed);
        }
        channel.observe_field_elems(rp);
        let r_i = channel.get_random_point();
        claim = lagrange_eval_at(rp, r_i);
        challenges.push(r_i);
    }

    let r_point: Vec<Block128> = challenges.iter().rev().cloned().collect();
    let eq_zr = noid_core::mle::eq::eq_ind(&z, &r_point);

    // --- Constraint composition check (AIR columns only) ---
    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    if proof.shift_partials.len() != shifted_indices.len() {
        return Err(VerifyError::ShapeMismatch);
    }
    let expected_ladder_len = log_len + 1;
    for partials in &proof.shift_partials {
        if partials.len() != expected_ladder_len {
            return Err(VerifyError::ShapeMismatch);
        }
    }
    let mut shifted_slot: Vec<Option<usize>> = vec![None; n_air_cols];
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        shifted_slot[col_id] = Some(slot);
    }
    let shifted_openings: Vec<Block128> = proof
        .shift_partials
        .iter()
        .map(|partials| crate::vshift::reconstruct_shifted_opening(&r_point, partials))
        .collect();

    crate::check_public_columns(air, &proof.base_openings, &r_point, log_len)?;

    let column_openings = &proof.base_openings;
    let mut composition = Block128::ZERO;
    let mut local_scratch: Vec<Block128> = Vec::new();
    let mut next_scratch: Vec<Block128> = Vec::new();
    for (k, c) in air.constraints().iter().enumerate() {
        local_scratch.clear();
        for &j in c.columns() {
            local_scratch.push(column_openings[j]);
        }
        next_scratch.clear();
        for &j in c.shifted_columns() {
            let slot = shifted_slot[j].ok_or(VerifyError::ShapeMismatch)?;
            next_scratch.push(shifted_openings[slot]);
        }
        let frame = noid_air::EvalFrame {
            local: &local_scratch,
            next: &next_scratch,
        };
        composition += betas[k] * c.evaluate(frame);
    }
    if eq_zr * composition != claim {
        return Err(VerifyError::ConstraintViolated);
    }

    // --- Absorb base openings + ladder partials on channel ---
    channel.observe_field_elems(&proof.base_openings);
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
    }

    // Absorb slice claimed values.
    channel.observe_field_elems(&proof.slice_claimed_values);

    // --- Multipoint sumcheck verify ---
    let s_count = shifted_indices.len();
    let gammas: Vec<Block128> = (0..s_count).map(|_| channel.get_random_point()).collect();

    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();
    let total_weights = n_air_cols + s_count + n_slices;
    let lambdas: Vec<Block128> = {
        let mut v = Vec::with_capacity(total_weights);
        let mut cur = Block128::ONE;
        for _ in 0..total_weights {
            v.push(cur);
            cur *= beta;
        }
        v
    };

    // Target = base + ladder + slice claims.
    let mut target = Block128::ZERO;
    for i in 0..n_air_cols {
        target += lambdas[i] * proof.base_openings[i];
    }
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        let t_s = crate::ladder_batch::target_claim(gammas[slot], partials);
        target += lambdas[n_air_cols + slot] * t_s;
    }
    for (i, sc) in slice_claims.iter().enumerate() {
        target += lambdas[n_air_cols + s_count + i] * sc.value;
    }

    let (sc_challenges, final_claim) = crate::multipoint_batch::verify_multipoint_sumcheck(
        &proof.multipoint_rounds,
        target,
        &mut channel,
    )?;
    let r_pp: Vec<Block128> = sc_challenges.iter().rev().cloned().collect();
    if r_pp.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }

    // Reconstruct terminal claim from mixed opening at r''.
    // The mixed opening proof provides all_openings: first n_total values
    // are column evaluations at r'' (the primary point).
    let m = &proof.mixed_opening.all_openings;
    if m.len() < n_total {
        return Err(VerifyError::ShapeMismatch);
    }
    let eq_base = noid_core::mle::eq::eq_ind(&r_point, &r_pp);
    let mut expected = Block128::ZERO;
    // Base contribution: AIR columns with eq(r_point, r'').
    for k in 0..n_air_cols {
        expected += lambdas[k] * eq_base * m[k];
    }
    // Ladder contribution.
    if s_count > 0 {
        let axes = crate::ladder_batch::LadderWeightAxes::new(&r_point, &r_pp);
        for (slot, &col_id) in shifted_indices.iter().enumerate() {
            let w_s = crate::ladder_batch::weight_at_axes(gammas[slot], &axes);
            expected += lambdas[n_air_cols + slot] * w_s * m[col_id];
        }
    }
    // Slice-claim contribution: eq(r_B_low, r'') * slice_col_opening.
    for (i, sc) in slice_claims.iter().enumerate() {
        let eq_s = noid_core::mle::eq::eq_ind(&sc.eval_point, &r_pp);
        expected += lambdas[n_air_cols + s_count + i] * eq_s * m[sc.col_index];
    }
    if expected != final_claim {
        return Err(VerifyError::ConstraintViolated);
    }

    // --- FRI-Binius mixed opening verify ---
    let secondary_claims: Vec<EvalClaim> = slice_claims
        .iter()
        .map(|sc| EvalClaim {
            col_index: sc.col_index,
            eval_point: sc.eval_point.clone(),
            value: sc.value,
        })
        .collect();

    verify_mixed_opening(
        &proof.commitment,
        &r_pp,
        &secondary_claims,
        &proof.mixed_opening,
        &ntt,
        &mut channel,
        &hasher,
    )
    .map_err(VerifyError::FriFailed)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Proof size estimation
// ---------------------------------------------------------------------------

impl InterleavedStarkProof {
    pub fn byte_len(&self) -> usize {
        let cap = self.commitment.cap.hashes.len() * 32;
        let base_openings = self.base_openings.len() * 16;
        let zc_rounds: usize = self.zero_check_rounds.iter().map(|r| r.len() * 16).sum();
        let shift_partials: usize = self.shift_partials.iter().map(|p| p.len() * 16).sum();
        let mp_rounds: usize = self.multipoint_rounds.iter().map(|r| r.len() * 16).sum();
        let mixed = self.mixed_opening.byte_len();
        let slices = self.slice_claimed_values.len() * 16;
        cap + base_openings + zc_rounds + shift_partials + mp_rounds + mixed + slices
    }
}
