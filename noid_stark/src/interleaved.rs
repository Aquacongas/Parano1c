// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::needless_range_loop)]

//! FRI-Binius interleaved PCS integration for the STARK.
//!
//! # Algebraic split
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
use std::time::{Duration, Instant};

use crate::{
    absorb_public_inputs, lagrange_eval_at, padded_log_len, round_poly_degree, RoundPoly,
    SliceClaim, VerifyError,
};

// ---------------------------------------------------------------------------
// Proof structures
// ---------------------------------------------------------------------------

/// Full STARK proof using the FRI-Binius interleaved PCS.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InterleavedStarkProof {
    pub log_rows: usize,
    pub commitment: InterleavedCommitment,
    /// MLE evaluations for every logical AIR column at the zero-check terminal point.
    ///
    /// Public columns remain in this per-proof transcript. Phase 5.1 omits them only
    /// from the block bucket PCS/mixed-opening surface; changing this vector would
    /// change algebraic transcript serialization and recursive replay, so it is
    /// intentionally deferred to the B2/G proof-shape work.
    pub base_openings: Vec<Block128>,
    pub zero_check_rounds: Vec<RoundPoly>,
    pub shift_partials: Vec<Vec<Block128>>,
    pub multipoint_rounds: Vec<RoundPoly>,
    pub mixed_opening: MixedOpeningProof,
    pub slice_claimed_values: Vec<Block128>,
}

/// Algebraic-only per-tx proof — no commitment header, no FRI opening.
/// Used by `noid_block` to accumulate N algebraic transcripts before
/// issuing one block-level FRI opening.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlgebraicStarkProof {
    pub log_rows: usize,
    /// MLE evaluations for every logical AIR column at the zero-check terminal point.
    ///
    /// Public columns remain in this per-tx algebraic transcript for now. Removing
    /// them saves only `16 * public_column_count` bytes per tx but changes transcript
    /// serialization and recursive replay, and may be subsumed by the B2/G binding
    /// redesign.
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

/// Verifier-side terminal data for an algebraic STARK transcript whose PCS
/// opening is discharged by an outer aggregator rather than by
/// [`verify_air_interleaved`].
///
/// The aggregator must check the sumcheck terminal identity against real column
/// openings at `r_pp`; otherwise the algebraic multipoint sumcheck is replayed
/// but not bound to the committed columns.
#[derive(Clone, Debug)]
pub struct AlgebraicTerminalData {
    pub r_pp: Vec<Block128>,
    pub final_claim: Block128,
    pub r_point: Vec<Block128>,
    pub gammas: Vec<Block128>,
    pub lambdas: Vec<Block128>,
    pub shifted_indices: Vec<usize>,
}

impl From<AlgebraicVerifyOut> for AlgebraicTerminalData {
    fn from(out: AlgebraicVerifyOut) -> Self {
        Self {
            r_pp: out.r_pp,
            final_claim: out.final_claim,
            r_point: out.r_point,
            gammas: out.gammas,
            lambdas: out.lambdas,
            shifted_indices: out.shifted_indices,
        }
    }
}

#[derive(Debug)]
struct AlgebraicPhaseTiming {
    name: &'static str,
    elapsed: Duration,
}

#[derive(Debug)]
struct AlgebraicProfiler {
    enabled: bool,
    started: Instant,
    last: Instant,
    phases: Vec<AlgebraicPhaseTiming>,
}

impl AlgebraicProfiler {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            enabled: prove_profile_enabled(),
            started: now,
            last: now,
            phases: Vec::with_capacity(16),
        }
    }

    fn phase(&mut self, name: &'static str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        self.phases.push(AlgebraicPhaseTiming {
            name,
            elapsed: now.duration_since(self.last),
        });
        self.last = now;
    }

    fn finish(
        self,
        log_rows: usize,
        log_len: usize,
        n_air_cols: usize,
        n_constraints: usize,
        n_shifted: usize,
        n_slice_claims: usize,
        n_extra_transcript: usize,
    ) {
        if !self.enabled {
            return;
        }
        let total = self.started.elapsed();
        let summary = self
            .phases
            .iter()
            .map(|p| format!("{}={:.3}ms", p.name, duration_ms(p.elapsed)))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "prove_block_profile stark_algebraic summary log_rows={} log_len={} n_air_cols={} n_constraints={} n_shifted={} n_slice_claims={} n_extra_transcript={} total_ms={:.3} phases={}",
            log_rows,
            log_len,
            n_air_cols,
            n_constraints,
            n_shifted,
            n_slice_claims,
            n_extra_transcript,
            duration_ms(total),
            summary
        );
    }
}

fn prove_profile_enabled() -> bool {
    std::env::var("NOID_PROVE_BLOCK_PROFILE")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn duration_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

fn public_column_flags<A: Air + ?Sized>(
    air: &A,
    n_air_cols: usize,
) -> Result<Vec<bool>, VerifyError> {
    let expected_rows = 1usize << air.log_rows();
    let mut flags = vec![false; n_air_cols];
    for pc in air.public_columns() {
        if pc.col >= n_air_cols || pc.values.len() != expected_rows || flags[pc.col] {
            return Err(VerifyError::ShapeMismatch);
        }
        flags[pc.col] = true;
    }
    Ok(flags)
}

fn committed_air_indices_from_public_flags(flags: &[bool]) -> Vec<usize> {
    flags
        .iter()
        .enumerate()
        .filter_map(|(idx, is_public)| (!*is_public).then_some(idx))
        .collect()
}

fn committed_column_positions(
    n_air_cols: usize,
    n_slices: usize,
    committed_air_indices: &[usize],
) -> Result<Vec<Option<usize>>, VerifyError> {
    let mut positions = vec![None; n_air_cols + n_slices];
    for (pos, &col_id) in committed_air_indices.iter().enumerate() {
        if col_id >= n_air_cols || positions[col_id].is_some() {
            return Err(VerifyError::ShapeMismatch);
        }
        positions[col_id] = Some(pos);
    }
    for i in 0..n_slices {
        positions[n_air_cols + i] = Some(committed_air_indices.len() + i);
    }
    Ok(positions)
}

fn public_openings_at_point<A: Air + ?Sized>(
    air: &A,
    point: &[Block128],
    log_len: usize,
    n_air_cols: usize,
) -> Result<Vec<Option<Block128>>, VerifyError> {
    if point.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }
    let expected_rows = 1usize << air.log_rows();
    let mut openings = vec![None; n_air_cols];
    let mut hi_factor: Vec<Block128> = vec![Block128::ONE; log_len + 1];
    for k in (0..log_len).rev() {
        hi_factor[k] = hi_factor[k + 1] * (Block128::ONE + point[k]);
    }
    let mut eq_tensors: Vec<Option<Vec<Block128>>> = (0..=log_len).map(|_| None).collect();
    for pc in air.public_columns() {
        if pc.col >= n_air_cols || pc.values.len() != expected_rows || openings[pc.col].is_some() {
            return Err(VerifyError::ShapeMismatch);
        }
        let k = pc.log_rows();
        if k > log_len {
            return Err(VerifyError::ShapeMismatch);
        }
        let values = pc.values.as_slice();
        let lo = if values.is_empty() {
            Block128::ZERO
        } else if values.iter().all(|v| *v == values[0]) {
            values[0]
        } else {
            let tensor = eq_tensors[k]
                .get_or_insert_with(|| noid_core::mle::eq::eq_ind_partial_eval(&point[..k]));
            let mut hi = values.len();
            while hi > 0 && values[hi - 1] == Block128::ZERO {
                hi -= 1;
            }
            let mut acc = Block128::ZERO;
            for i in 0..hi {
                acc += tensor[i] * values[i];
            }
            acc
        };
        openings[pc.col] = Some(hi_factor[k] * lo);
    }
    Ok(openings)
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
    let mut profiler = AlgebraicProfiler::new();
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
    profiler.phase("transcript_setup");

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
    profiler.phase("shifted_column_prep");

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
    let (zero_check_rounds, r) = crate::prove_zero_check_with_domains_and_air_log_rows(
        &sumcheck_cols,
        air.constraints(),
        &betas,
        &z,
        channel,
        degree,
        &shifted_slot,
        n_air_cols,
        &sumcheck_domains,
        air.log_rows(),
    );
    let r_point: Vec<Block128> = r.iter().rev().cloned().collect();
    profiler.phase("zero_check_sumcheck");

    // M2 + flat-basis: clmul_gcm-based fold is ~7x faster than tower-basis mul.
    // Thread-local u128 scratch avoids per-call allocation.
    thread_local! {
        static FLAT_SCRATCH: std::cell::RefCell<Vec<u128>> =
            const { std::cell::RefCell::new(Vec::new()) };
        static PT_FLAT: std::cell::RefCell<Vec<u128>> =
            const { std::cell::RefCell::new(Vec::new()) };
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
    profiler.phase("base_openings");

    // VSHIFT ladder partials.
    let partials_per_slot: Vec<Vec<Block128>> = shifted_indices
        .par_iter()
        .map(|&col_id| crate::vshift::ladder_partials(padded_columns[col_id], &r_point))
        .collect();
    for (slot, partials) in partials_per_slot.iter().enumerate() {
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
    }
    profiler.phase("vshift_ladder_partials");

    let slice_values: Vec<Block128> = slice_claims.iter().map(|sc| sc.value).collect();
    channel.observe_field_elems(&slice_values);
    profiler.phase("slice_claim_absorb");

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
    profiler.phase("multipoint_challenges");

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
    // Build the combined base B table directly in flat/GCM basis for the
    // multipoint prover's flat-B fast path. This is the same polynomial
    // Σ_i λ_i·MLE_i(x), but avoids materializing it in tower basis only for
    // `prove_multipoint_sumcheck` to immediately flatten it again.
    use noid_core::hardware::{clmul_gcm, tower_to_flat_u128};
    let mut combined_base_b_flat: Vec<u128> = vec![0; hyper_len];
    for i in 0..n_air_cols {
        let lam_flat = tower_to_flat_u128(lambdas[i].0);
        let col = padded_columns[i];
        combined_base_b_flat
            .par_iter_mut()
            .zip(col.par_iter())
            .for_each(|(acc, &val)| *acc ^= clmul_gcm(lam_flat, tower_to_flat_u128(val.0)));
    }
    profiler.phase("combined_base_b_flat");

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
    let ladder_pairs_b_flat: Vec<Vec<u128>> = (0..s_count)
        .into_par_iter()
        .map(|slot| {
            padded_columns[shifted_indices[slot]]
                .iter()
                .map(|v| tower_to_flat_u128(v.0))
                .collect()
        })
        .collect();
    profiler.phase("ladder_pairs");

    let slice_pairs_a: Vec<Vec<Block128>> = (0..n_slices)
        .into_par_iter()
        .map(|i| {
            let lam = lambdas[n_air_cols + s_count + i];
            let eq_s = eq_ind_partial_eval(&slice_claims[i].eval_point);
            eq_s.into_iter().map(|v| v * lam).collect()
        })
        .collect();
    let slice_pairs_b_flat: Vec<Vec<u128>> = (0..n_slices)
        .into_par_iter()
        .map(|i| {
            padded_columns[slice_claims[i].col_index]
                .iter()
                .map(|v| tower_to_flat_u128(v.0))
                .collect()
        })
        .collect();
    profiler.phase("slice_pairs");

    let mut pairs_a: Vec<Vec<Block128>> = Vec::with_capacity(1 + s_count + n_slices);
    pairs_a.push(eq_base);
    pairs_a.extend(ladder_pairs_a);
    pairs_a.extend(slice_pairs_a);
    let mut pairs_b_flat: Vec<Vec<u128>> = Vec::with_capacity(1 + s_count + n_slices);
    pairs_b_flat.push(combined_base_b_flat);
    pairs_b_flat.extend(ladder_pairs_b_flat);
    pairs_b_flat.extend(slice_pairs_b_flat);

    let (multipoint_rounds, mp_challenges) =
        crate::multipoint_batch::prove_multipoint_sumcheck_flat_b(
            pairs_a,
            pairs_b_flat,
            target,
            channel,
        );
    let r_pp: Vec<Block128> = mp_challenges.iter().rev().cloned().collect();
    debug_assert_eq!(r_pp.len(), log_len);
    profiler.phase("multipoint_sumcheck");

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
    profiler.phase("final_claim_and_proof_assembly");
    profiler.finish(
        log_rows,
        log_len,
        n_air_cols,
        n_constraints,
        shifted_indices.len(),
        slice_claims.len(),
        extra_transcript.len(),
    );
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
    verify_air_interleaved_algebraic_with_log_len(
        air,
        pi,
        proof,
        extra_transcript,
        slice_claims,
        None,
        channel,
    )
}

/// Replay an algebraic STARK transcript and return the extra terminal data an
/// outer aggregation verifier needs to bind the sumcheck terminal claim to PCS
/// openings. The historical API above returns only `(r_pp, final_claim,
/// lambdas)` and is kept for compatibility.
pub fn verify_air_interleaved_algebraic_terminal<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &AlgebraicStarkProof,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    channel: &mut Channel,
) -> Result<AlgebraicTerminalData, VerifyError> {
    let out = verify_algebraic_inner(
        air,
        pi,
        proof.into(),
        extra_transcript,
        slice_claims,
        None,
        channel,
    )?;
    Ok(out.into())
}

/// Like `verify_air_interleaved_algebraic` but with an optional explicit log_len.
/// When `log_len_override = Some(len)`, uses `len` instead of
/// `padded_log_len(proof.log_rows)`.
#[allow(clippy::too_many_arguments)]
pub fn verify_air_interleaved_algebraic_with_log_len<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &AlgebraicStarkProof,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    log_len_override: Option<usize>,
    channel: &mut Channel,
) -> Result<(Vec<Block128>, Block128, Vec<Block128>), VerifyError> {
    let out = verify_algebraic_inner(
        air,
        pi,
        proof.into(),
        extra_transcript,
        slice_claims,
        log_len_override,
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
    log_len_override: Option<usize>,
    channel: &mut Channel,
) -> Result<AlgebraicVerifyOut, VerifyError> {
    let n_air_cols = air.n_columns();
    let n_slices = slice_claims.len();

    // proof.log_rows holds the committed log_len, which may be >= air.log_rows()
    // when a caller pads columns to a larger global domain.
    if proof.log_rows < air.log_rows() {
        tracing::warn!(
            proof_log_rows = proof.log_rows,
            air_log_rows = air.log_rows(),
            "SHAPE1: log_rows too small"
        );
        return Err(VerifyError::ShapeMismatch);
    }
    if proof.base_openings.len() != n_air_cols {
        tracing::warn!(
            got = proof.base_openings.len(),
            want = n_air_cols,
            "SHAPE2: base_openings"
        );
        return Err(VerifyError::ShapeMismatch);
    }

    // If an explicit log_len was provided for columns padded to a larger domain,
    // use it; otherwise derive from proof.log_rows.
    let log_len = log_len_override.unwrap_or_else(|| padded_log_len(proof.log_rows));
    if proof.zero_check_rounds.len() != log_len {
        tracing::warn!(
            got = proof.zero_check_rounds.len(),
            want = log_len,
            "SHAPE3: zero_check_rounds"
        );
        return Err(VerifyError::ShapeMismatch);
    }
    let degree = round_poly_degree(air);
    let n_points = degree + 1;
    for rp in proof.zero_check_rounds {
        if rp.len() != n_points {
            tracing::warn!(
                got = rp.len(),
                want = n_points,
                "SHAPE4: zero_check round_poly_degree"
            );
            return Err(VerifyError::ShapeMismatch);
        }
    }
    if proof.multipoint_rounds.len() != log_len {
        tracing::warn!(
            got = proof.multipoint_rounds.len(),
            want = log_len,
            "SHAPE5: multipoint_rounds"
        );
        return Err(VerifyError::ShapeMismatch);
    }
    for rp in proof.multipoint_rounds {
        if rp.len() != crate::multipoint_batch::MULTIPOINT_ROUND_POINTS {
            tracing::warn!("SHAPE6: multipoint round points");
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
        tracing::warn!(
            got = proof.shift_partials.len(),
            want = shifted_indices.len(),
            "SHAPE7: shift_partials"
        );
        return Err(VerifyError::ShapeMismatch);
    }
    let expected_ladder_len = log_len + 1;
    for partials in proof.shift_partials {
        if partials.len() != expected_ladder_len {
            tracing::warn!(
                got = partials.len(),
                want = expected_ladder_len,
                "SHAPE8: shift_partials ladder"
            );
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
        composition += betas[k] * c.evaluate_at_point(frame, &r_point, air.log_rows());
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
pub fn prove_air_interleaved_from_refs<'cols, A: Air + ?Sized>(
    air: &A,
    padded_columns: &[&'cols [Block128]],
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
    let n_air_cols = air.n_columns();
    let n_slices = slice_claims.len();
    assert_eq!(
        padded_columns.len(),
        n_air_cols + n_slices,
        "interleaved STARK expects AIR columns followed by slice columns"
    );
    let public_flags =
        public_column_flags(air, n_air_cols).expect("invalid public column metadata");
    let committed_air_indices = committed_air_indices_from_public_flags(&public_flags);
    let committed_positions =
        committed_column_positions(n_air_cols, n_slices, &committed_air_indices)
            .expect("invalid committed column map");
    let mut committed_refs: Vec<&'cols [Block128]> =
        Vec::with_capacity(committed_air_indices.len() + n_slices);
    for &col_id in &committed_air_indices {
        committed_refs.push(padded_columns[col_id]);
    }
    for i in 0..n_slices {
        committed_refs.push(padded_columns[n_air_cols + i]);
    }

    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    let (commitment, prover_state) = match pre_committed {
        Some(pre) => pre,
        None => interleaved_commit(&committed_refs, &ntt, &hasher),
    };
    assert_eq!(commitment.n_cols, committed_refs.len());

    let mut channel = Channel::new();
    absorb_cap(&mut channel, &commitment.cap);

    let (alg, r_pp, _final_claim, _lambdas) = prove_air_interleaved_algebraic(
        air,
        padded_columns,
        pi,
        extra_transcript,
        slice_claims,
        log_len,
        &mut channel,
    );

    let secondary_claims: Vec<EvalClaim> = slice_claims
        .iter()
        .map(|sc| EvalClaim {
            col_index: committed_positions
                .get(sc.col_index)
                .and_then(|p| *p)
                .expect("slice claim must target a committed extended column"),
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
    let col_refs: Vec<&'cols [Block128]> = padded_columns.iter().map(|c| c.as_slice()).collect();
    prove_air_interleaved_from_refs(
        air,
        &col_refs,
        pi,
        extra_transcript,
        slice_claims,
        log_len,
        pre_committed,
        num_queries,
    )
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
    let public_flags = public_column_flags(air, n_air_cols)?;
    let committed_air_indices = committed_air_indices_from_public_flags(&public_flags);
    let committed_positions =
        committed_column_positions(n_air_cols, n_slices, &committed_air_indices)?;
    let n_committed = committed_air_indices.len() + n_slices;

    if proof.log_rows != air.log_rows() {
        return Err(VerifyError::ShapeMismatch);
    }
    if proof.commitment.n_cols != n_committed {
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
        None, // no log_len override for full verify_air_interleaved
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

    // Verify terminal identity against public programme openings plus
    // FRI-supplied committed openings. Public AIR columns are not committed and
    // therefore do not pay source-binding bytes.
    let m = &proof.mixed_opening.all_openings;
    if m.len() < n_committed {
        return Err(VerifyError::ShapeMismatch);
    }
    let public_openings = public_openings_at_point(air, &r_pp, log_len, n_air_cols)?;
    let column_opening = |col_id: usize| -> Result<Block128, VerifyError> {
        if col_id >= n_total {
            return Err(VerifyError::ShapeMismatch);
        }
        if col_id < n_air_cols {
            if let Some(value) = public_openings[col_id] {
                return Ok(value);
            }
        }
        let pos = committed_positions[col_id].ok_or(VerifyError::ShapeMismatch)?;
        Ok(m[pos])
    };

    let eq_base = noid_core::mle::eq::eq_ind(&r_point, &r_pp);
    let mut expected = Block128::ZERO;
    for k in 0..n_air_cols {
        expected += lambdas[k] * eq_base * column_opening(k)?;
    }
    if s_count > 0 {
        let axes = crate::ladder_batch::LadderWeightAxes::new(&r_point, &r_pp);
        for (slot, &col_id) in shifted_indices.iter().enumerate() {
            let w_s = crate::ladder_batch::weight_at_axes(gammas[slot], &axes);
            expected += lambdas[n_air_cols + slot] * w_s * column_opening(col_id)?;
        }
    }
    for (i, sc) in slice_claims.iter().enumerate() {
        let eq_s = noid_core::mle::eq::eq_ind(&sc.eval_point, &r_pp);
        expected += lambdas[n_air_cols + s_count + i] * eq_s * column_opening(sc.col_index)?;
    }
    if expected != final_claim {
        return Err(VerifyError::ConstraintViolated);
    }

    let secondary_claims: Vec<EvalClaim> = slice_claims
        .iter()
        .map(|sc| {
            let col_index = committed_positions
                .get(sc.col_index)
                .and_then(|p| *p)
                .ok_or(VerifyError::ShapeMismatch)?;
            Ok(EvalClaim {
                col_index,
                eval_point: sc.eval_point.clone(),
                value: sc.value,
            })
        })
        .collect::<Result<Vec<_>, VerifyError>>()?;

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
