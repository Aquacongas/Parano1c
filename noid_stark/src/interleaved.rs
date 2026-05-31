// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop)]

//! FRI-Binius interleaved PCS integration for the STARK.
//!
//! # Algebraic split (Stage G)
//!
//! `prove_air_interleaved_algebraic` / `verify_air_interleaved_algebraic`
//! run every algebraic step (zero-check, base openings, ladder partials,
//! multipoint sumcheck) on a **caller-supplied** shared `Channel`,
//! stopping just before the FRI mixed opening.  The caller is responsible
//! for:
//!
//! 1. Absorbing the interleaved Merkle cap into `channel` **before** the
//!    call (so the Fiat-Shamir transcript is correctly bound to the
//!    commitment).
//! 2. Issuing the FRI mixed opening after the call, using the returned
//!    `r_pp` as the primary opening point and `final_claim` as the
//!    value that must be matched.
//!
//! `prove_air_interleaved` / `verify_air_interleaved` are byte-identical
//! to their pre-split form; they construct the channel internally and
//! delegate to the algebraic variants.

use noid_air::Air;
use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::mle::evaluate::evaluate_flat_with_scratch;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::Channel;
use noid_fri_binius::{
    absorb_cap, interleaved_commit, prove_mixed_opening, verify_mixed_opening, EvalClaim,
    InterleavedCommitment, MixedOpeningProof,
};
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_tx::PublicInputs;
use rayon::prelude::*;

use crate::{
    absorb_public_inputs, lagrange_eval_at, padded_log_len, round_poly_degree, RoundPoly,
    SliceClaim, VerifyError,
};

// ---------------------------------------------------------------------------
// Proof structures
// ---------------------------------------------------------------------------

/// Full STARK proof using the FRI-Binius interleaved PCS.
#[derive(Debug, Clone)]
pub struct InterleavedStarkProof {
    pub log_rows: usize,
    pub commitment: InterleavedCommitment,
    pub base_openings: Vec<Block128>,
    pub zero_check_rounds: Vec<RoundPoly>,
    pub shift_partials: Vec<Vec<Block128>>,
    pub multipoint_rounds: Vec<RoundPoly>,
    pub mixed_opening: MixedOpeningProof,
    pub slice_claimed_values: Vec<Block128>,
}

/// Algebraic-only per-tx proof — no commitment header, no FRI opening.
/// Used by `noid_block` (Stage G) to accumulate N algebraic transcripts
/// before issuing one block-level FRI.
#[derive(Debug, Clone)]
pub struct AlgebraicStarkProof {
    pub log_rows: usize,
    pub base_openings: Vec<Block128>,
    pub zero_check_rounds: Vec<RoundPoly>,
    pub shift_partials: Vec<Vec<Block128>>,
    pub multipoint_rounds: Vec<RoundPoly>,
    pub slice_claimed_values: Vec<Block128>,
}

impl AlgebraicStarkProof {
    pub fn byte_len(&self) -> usize {
        self.base_openings.len() * 16
            + self
                .zero_check_rounds
                .iter()
                .map(|r| r.len() * 16)
                .sum::<usize>()
            + self
                .shift_partials
                .iter()
                .map(|p| p.len() * 16)
                .sum::<usize>()
            + self
                .multipoint_rounds
                .iter()
                .map(|r| r.len() * 16)
                .sum::<usize>()
            + self.slice_claimed_values.len() * 16
    }
}

// ---------------------------------------------------------------------------
// Algebraic verifier borrow-view (eliminates clone in verify_air_interleaved)
// ---------------------------------------------------------------------------

/// Zero-copy view of an [`AlgebraicStarkProof`] for [`verify_algebraic_inner`].
/// Created via `proof.into()` — no heap allocation; all fields borrow from the
/// original proof.  This avoids the ~4 KB clone that the wrapper previously
/// performed just to satisfy `verify_algebraic_inner`'s type signature.
struct AlgebraicStarkProofRef<'a> {
    log_rows: usize,
    base_openings: &'a [Block128],
    zero_check_rounds: &'a [RoundPoly],
    shift_partials: &'a [Vec<Block128>],
    multipoint_rounds: &'a [RoundPoly],
    slice_claimed_values: &'a [Block128],
}

impl<'a> From<&'a AlgebraicStarkProof> for AlgebraicStarkProofRef<'a> {
    fn from(p: &'a AlgebraicStarkProof) -> Self {
        Self {
            log_rows: p.log_rows,
            base_openings: &p.base_openings,
            zero_check_rounds: &p.zero_check_rounds,
            shift_partials: &p.shift_partials,
            multipoint_rounds: &p.multipoint_rounds,
            slice_claimed_values: &p.slice_claimed_values,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helper: algebraic verifier extended output
// ---------------------------------------------------------------------------

/// Everything the full verifier needs to finish after the algebraic replay.
struct AlgebraicVerifyOut {
    r_pp: Vec<Block128>,
    final_claim: Block128,
    r_point: Vec<Block128>,
    gammas: Vec<Block128>,
    lambdas: Vec<Block128>,
    shifted_indices: Vec<usize>,
}

// ---------------------------------------------------------------------------
// Algebraic prover core
// ---------------------------------------------------------------------------

/// Run all algebraic STARK steps (zero-check, base openings, VSHIFT
/// ladder partials, multipoint sumcheck) into the provided `channel`.
///
/// **Pre-condition:** caller has already called `absorb_cap(channel, cap)`
/// before this function.  `absorb_public_inputs` is called here first,
/// then the rest of the algebraic transcript follows.
///
/// Returns `(proof, r_pp, final_claim)`:
/// - `r_pp`        – multipoint terminal challenge (length `log_len`).
/// - `final_claim` – value that the FRI opening at `r_pp` must satisfy.
#[allow(clippy::too_many_arguments)]
pub fn prove_air_interleaved_algebraic<A: Air + ?Sized>(
    air: &A,
    padded_columns: &[&[Block128]],
    pi: &PublicInputs,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    log_len: usize,
    channel: &mut Channel,
) -> (AlgebraicStarkProof, Vec<Block128>, Block128, Vec<Block128>) {
    let log_rows = air.log_rows();
    let n_air_cols = air.n_columns();

    absorb_public_inputs(channel, pi);
    if !extra_transcript.is_empty() {
        channel.observe_field_elems(extra_transcript);
    }

    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    // Zero-check sumcheck.
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
        .map(|&col_id| crate::vshift::cyclic_rotate_left(padded_columns[col_id]))
        .collect();
    let mut sumcheck_cols: Vec<&[Block128]> =
        Vec::with_capacity(n_air_cols + rotated_columns.len());
    // Zero-copy: extend with refs already in padded_columns.
    sumcheck_cols.extend_from_slice(&padded_columns[..n_air_cols]);
    for col in &rotated_columns {
        sumcheck_cols.push(col.as_slice());
    }

    // Tower Sumcheck: get column domains for boolean fast-path.
    // Base columns [0..n_air_cols] from the AIR, rotated columns inherit source domain.
    let mut sumcheck_domains = air.column_domains();
    // Rotated (shifted) columns share their source column's domain.
    for &col_id in &shifted_indices {
        let d = if col_id < sumcheck_domains.len() {
            sumcheck_domains[col_id]
        } else {
            noid_air::ColumnDomain::Block128
        };
        sumcheck_domains.push(d);
    }

    let degree = round_poly_degree(air);
    let (zero_check_rounds, r) = crate::prove_zero_check_with_domains(
        &sumcheck_cols,
        air.constraints(),
        &betas,
        &z,
        channel,
        degree,
        &shifted_slot,
        n_air_cols,
        &sumcheck_domains,
    );
    let r_point: Vec<Block128> = r.iter().rev().cloned().collect();

    // M2 + flat-basis: clmul_gcm-based fold is ~7x faster than tower-basis mul.
    // Thread-local u128 scratch avoids per-call allocation.
    thread_local! {
        static FLAT_SCRATCH: std::cell::RefCell<Vec<u128>> =
            std::cell::RefCell::new(Vec::new());
        static PT_FLAT: std::cell::RefCell<Vec<u128>> =
            std::cell::RefCell::new(Vec::new());
    }
    let base_openings: Vec<Block128> = padded_columns[..n_air_cols]
        .par_iter()
        .copied()
        .map(|col| {
            FLAT_SCRATCH.with(|fs| {
                PT_FLAT.with(|pf| {
                    evaluate_flat_with_scratch(
                        col,
                        &r_point,
                        &mut fs.borrow_mut(),
                        &mut pf.borrow_mut(),
                    )
                })
            })
        })
        .collect();
    channel.observe_field_elems(&base_openings);

    // VSHIFT ladder partials.
    let partials_per_slot: Vec<Vec<Block128>> = shifted_indices
        .par_iter()
        .map(|&col_id| crate::vshift::ladder_partials(padded_columns[col_id], &r_point))
        .collect();
    for (slot, partials) in partials_per_slot.iter().enumerate() {
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
    }

    let slice_values: Vec<Block128> = slice_claims.iter().map(|sc| sc.value).collect();
    channel.observe_field_elems(&slice_values);

    // Multipoint sumcheck.
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

    let eq_base = eq_ind_partial_eval(&r_point);
    let hyper_len = 1usize << log_len;
    // Cache-friendly column-outer accumulation for combined_base_b.
    // Processing one column at a time (128 KB) keeps both combined_base_b
    // and the current column in L2 cache, avoiding L3/DRAM thrashing that
    // the previous row-outer layout caused (81 columns × random stride).
    let mut combined_base_b: Vec<Block128> = vec![Block128::ZERO; hyper_len];
    for i in 0..n_air_cols {
        let lam = lambdas[i];
        let col = padded_columns[i];
        combined_base_b
            .par_iter_mut()
            .zip(col.par_iter())
            .for_each(|(acc, &val)| *acc += lam * val);
    }

    let weight_trails = if s_count > 0 {
        Some(crate::ladder_batch::WeightTrails::new(&r_point))
    } else {
        None
    };
    let ladder_pairs_a: Vec<Vec<Block128>> = (0..s_count)
        .into_par_iter()
        .map(|slot| {
            let trails = weight_trails.as_ref().expect("trails present");
            let mut w = crate::ladder_batch::build_weight_table_from_trails(gammas[slot], trails);
            let eta = lambdas[n_air_cols + slot];
            for v in w.iter_mut() {
                *v *= eta;
            }
            w
        })
        .collect();
    let ladder_pairs_b: Vec<&[Block128]> = (0..s_count)
        .map(|slot| padded_columns[shifted_indices[slot]])
        .collect();

    let slice_pairs_a: Vec<Vec<Block128>> = (0..n_slices)
        .into_par_iter()
        .map(|i| {
            let lam = lambdas[n_air_cols + s_count + i];
            let eq_s = eq_ind_partial_eval(&slice_claims[i].eval_point);
            eq_s.into_iter().map(|v| v * lam).collect()
        })
        .collect();
    let slice_pairs_b: Vec<&[Block128]> = (0..n_slices)
        .map(|i| padded_columns[slice_claims[i].col_index])
        .collect();

    let mut pairs_a: Vec<Vec<Block128>> = Vec::with_capacity(1 + s_count + n_slices);
    pairs_a.push(eq_base);
    pairs_a.extend(ladder_pairs_a);
    pairs_a.extend(slice_pairs_a);
    let mut pairs_b: Vec<&[Block128]> = Vec::with_capacity(1 + s_count + n_slices);
    pairs_b.push(combined_base_b.as_slice());
    pairs_b.extend(ladder_pairs_b);
    pairs_b.extend(slice_pairs_b);

    let (multipoint_rounds, mp_challenges) =
        crate::multipoint_batch::prove_multipoint_sumcheck(pairs_a, pairs_b, target, channel);
    let r_pp: Vec<Block128> = mp_challenges.iter().rev().cloned().collect();
    debug_assert_eq!(r_pp.len(), log_len);

    // Derive final_claim. The sumcheck terminal claim is the value of the
    // last round polynomial at the last challenge (or `target` when there
    // are zero rounds, i.e. log_len == 0). This matches
    // `verify_multipoint_sumcheck`'s post-loop return value bit-for-bit.
    let final_claim = match (multipoint_rounds.last(), mp_challenges.last()) {
        (Some(last_rp), Some(&last_ch)) => crate::lagrange_eval_at_pub(last_rp, last_ch),
        _ => target,
    };

    let proof = AlgebraicStarkProof {
        log_rows,
        base_openings,
        zero_check_rounds,
        shift_partials: partials_per_slot,
        multipoint_rounds,
        slice_claimed_values: slice_values,
    };
    (proof, r_pp, final_claim, lambdas)
}

// ---------------------------------------------------------------------------
// Algebraic verifier core
// ---------------------------------------------------------------------------

/// Replay all algebraic steps on the provided `channel`.
///
/// **Pre-condition:** caller has already called `absorb_cap(channel, cap)`.
///
/// Returns `(r_pp, final_claim)` on success.  The caller must then verify
/// the FRI mixed opening for `r_pp` / `final_claim` and check the terminal
/// identity `expected == final_claim` using the FRI-supplied openings.
#[allow(clippy::too_many_arguments)]
pub fn verify_air_interleaved_algebraic<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &AlgebraicStarkProof,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    channel: &mut Channel,
) -> Result<(Vec<Block128>, Block128, Vec<Block128>), VerifyError> {
    let out = verify_algebraic_inner(
        air,
        pi,
        proof.into(),
        extra_transcript,
        slice_claims,
        channel,
    )?;
    Ok((out.r_pp, out.final_claim, out.lambdas))
}

/// Internal variant that also returns the data needed by the full verifier
/// to reconstruct the terminal identity.
fn verify_algebraic_inner<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: AlgebraicStarkProofRef<'_>,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    channel: &mut Channel,
) -> Result<AlgebraicVerifyOut, VerifyError> {
    let n_air_cols = air.n_columns();
    let n_slices = slice_claims.len();

    if proof.log_rows != air.log_rows() {
        return Err(VerifyError::ShapeMismatch);
    }
    if proof.base_openings.len() != n_air_cols {
        return Err(VerifyError::ShapeMismatch);
    }

    let log_len = padded_log_len(proof.log_rows);
    if proof.zero_check_rounds.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }
    let degree = round_poly_degree(air);
    let n_points = degree + 1;
    for rp in proof.zero_check_rounds {
        if rp.len() != n_points {
            return Err(VerifyError::ShapeMismatch);
        }
    }
    if proof.multipoint_rounds.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }
    for rp in proof.multipoint_rounds {
        if rp.len() != crate::multipoint_batch::MULTIPOINT_ROUND_POINTS {
            return Err(VerifyError::ShapeMismatch);
        }
    }

    absorb_public_inputs(channel, pi);
    if !extra_transcript.is_empty() {
        channel.observe_field_elems(extra_transcript);
    }
    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    // Zero-check replay.
    let mut zc_claim = Block128::ZERO;
    let mut zc_challenges: Vec<Block128> = Vec::with_capacity(log_len);
    for rp in proof.zero_check_rounds {
        if rp[0] + rp[1] != zc_claim {
            return Err(VerifyError::ZeroCheckFailed);
        }
        channel.observe_field_elems(rp);
        let r_i = channel.get_random_point();
        zc_claim = lagrange_eval_at(rp, r_i);
        zc_challenges.push(r_i);
    }

    let r_point: Vec<Block128> = zc_challenges.iter().rev().cloned().collect();
    let eq_zr = noid_core::mle::eq::eq_ind(&z, &r_point);

    // Constraint composition check.
    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    if proof.shift_partials.len() != shifted_indices.len() {
        return Err(VerifyError::ShapeMismatch);
    }
    let expected_ladder_len = log_len + 1;
    for partials in proof.shift_partials {
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
        .map(|p| crate::vshift::reconstruct_shifted_opening(&r_point, p))
        .collect();

    crate::check_public_columns(air, proof.base_openings, &r_point, log_len)?;

    let mut composition = Block128::ZERO;
    let mut local_scratch: Vec<Block128> = Vec::new();
    let mut next_scratch: Vec<Block128> = Vec::new();
    for (k, c) in air.constraints().iter().enumerate() {
        local_scratch.clear();
        for &j in c.columns() {
            local_scratch.push(proof.base_openings[j]);
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
    if eq_zr * composition != zc_claim {
        return Err(VerifyError::ConstraintViolated);
    }

    // Absorb base openings + ladder partials + slice values.
    channel.observe_field_elems(proof.base_openings);
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
    }
    channel.observe_field_elems(proof.slice_claimed_values);

    // Multipoint sumcheck replay.
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

    let mut mp_target = Block128::ZERO;
    for i in 0..n_air_cols {
        mp_target += lambdas[i] * proof.base_openings[i];
    }
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        let t_s = crate::ladder_batch::target_claim(gammas[slot], partials);
        mp_target += lambdas[n_air_cols + slot] * t_s;
    }
    for (i, sc) in slice_claims.iter().enumerate() {
        mp_target += lambdas[n_air_cols + s_count + i] * sc.value;
    }

    let (sc_challenges, final_claim) = crate::multipoint_batch::verify_multipoint_sumcheck(
        proof.multipoint_rounds,
        mp_target,
        channel,
    )?;
    let r_pp: Vec<Block128> = sc_challenges.iter().rev().cloned().collect();
    if r_pp.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }

    Ok(AlgebraicVerifyOut {
        r_pp,
        final_claim,
        r_point,
        gammas,
        lambdas,
        shifted_indices,
    })
}

// ---------------------------------------------------------------------------
// Full prover (byte-identical to pre-split)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn prove_air_interleaved<'cols, A: Air + ?Sized>(
    air: &A,
    padded_columns: &'cols [Vec<Block128>],
    pi: &PublicInputs,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    log_len: usize,
    pre_committed: Option<(
        InterleavedCommitment,
        noid_fri_binius::InterleavedProverState<'cols>,
    )>,
    num_queries: usize,
) -> InterleavedStarkProof {
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    let col_refs: Vec<&'cols [Block128]> = padded_columns.iter().map(|c| c.as_slice()).collect();
    let (commitment, prover_state) = match pre_committed {
        Some(pre) => pre,
        None => interleaved_commit(&col_refs, &ntt, &hasher),
    };

    let mut channel = Channel::new();
    absorb_cap(&mut channel, &commitment.cap);

    // Collect slice refs: prove_air_interleaved_algebraic takes &[&[Block128]].
    let col_refs: Vec<&[Block128]> = padded_columns.iter().map(|c| c.as_slice()).collect();
    let (alg, r_pp, _final_claim, _lambdas) = prove_air_interleaved_algebraic(
        air,
        &col_refs,
        pi,
        extra_transcript,
        slice_claims,
        log_len,
        &mut channel,
    );

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
        num_queries,
    );

    InterleavedStarkProof {
        log_rows: alg.log_rows,
        commitment,
        base_openings: alg.base_openings,
        zero_check_rounds: alg.zero_check_rounds,
        shift_partials: alg.shift_partials,
        multipoint_rounds: alg.multipoint_rounds,
        mixed_opening,
        slice_claimed_values: alg.slice_claimed_values,
    }
}

// ---------------------------------------------------------------------------
// Full verifier (byte-identical to pre-split)
// ---------------------------------------------------------------------------

pub fn verify_air_interleaved<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &InterleavedStarkProof,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    num_queries: usize,
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
    let hasher = Poseidon2bSponge::new();

    // Build a zero-copy borrow view — avoids cloning all proof vectors.
    let alg_ref = AlgebraicStarkProofRef {
        log_rows: proof.log_rows,
        base_openings: &proof.base_openings,
        zero_check_rounds: &proof.zero_check_rounds,
        shift_partials: &proof.shift_partials,
        multipoint_rounds: &proof.multipoint_rounds,
        slice_claimed_values: &proof.slice_claimed_values,
    };

    let mut channel = Channel::new();
    absorb_cap(&mut channel, &proof.commitment.cap);

    // Run the algebraic verifier; it advances channel to just before FRI.
    let out = verify_algebraic_inner(
        air,
        pi,
        alg_ref,
        extra_transcript,
        slice_claims,
        &mut channel,
    )?;

    let AlgebraicVerifyOut {
        r_pp,
        final_claim,
        r_point,
        gammas,
        lambdas,
        shifted_indices,
    } = out;

    let s_count = shifted_indices.len();

    // Verify terminal identity against FRI-supplied openings.
    let m = &proof.mixed_opening.all_openings;
    if m.len() < n_total {
        return Err(VerifyError::ShapeMismatch);
    }

    let eq_base = noid_core::mle::eq::eq_ind(&r_point, &r_pp);
    let mut expected = Block128::ZERO;
    for k in 0..n_air_cols {
        expected += lambdas[k] * eq_base * m[k];
    }
    if s_count > 0 {
        let axes = crate::ladder_batch::LadderWeightAxes::new(&r_point, &r_pp);
        for (slot, &col_id) in shifted_indices.iter().enumerate() {
            let w_s = crate::ladder_batch::weight_at_axes(gammas[slot], &axes);
            expected += lambdas[n_air_cols + slot] * w_s * m[col_id];
        }
    }
    for (i, sc) in slice_claims.iter().enumerate() {
        let eq_s = noid_core::mle::eq::eq_ind(&sc.eval_point, &r_pp);
        expected += lambdas[n_air_cols + s_count + i] * eq_s * m[sc.col_index];
    }
    if expected != final_claim {
        return Err(VerifyError::ConstraintViolated);
    }

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
        num_queries,
    )
    .map_err(VerifyError::FriFailed)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Proof size
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
