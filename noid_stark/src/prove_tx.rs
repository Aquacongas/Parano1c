// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Production orchestrator: `prove_tx` / `verify_tx`.
//!
//! Stage 0 "MLE Splitting" path. Single-transcript, single FRI group:
//!
//! 1. Seed one `Poseidon2bChannel` with `PublicInputs`.
//! 2. Build Spine boundary MLE (2^15); slice into 4 columns of 2^13.
//! 3. Build Auth boundary MLE (2^14); slice into 2 columns of 2^13.
//! 4. Append all 6 slice columns to the trace. Commit all columns
//!    uniformly at log_len=13.
//! 5. Absorb slice commitments (indices 291..297) into GKR channels.
//! 6. Run SpineGKR Kill-Shot, then AuthGKR Kill-Shot.
//! 7. Thread both `(r_B, v_B)` reductions into STARK `extra_transcript`.
//! 8. STARK prove: zero-check + uniform multipoint close (with slice
//!    claims injected) + single batched FRI opening for all 297 columns.
//!
//! The verifier replays in the same order, reconstructs the original
//! MLE values from slice openings via `reconstruct_from_slices`, and
//! checks against the GKR reduction values.

use noid_air::{Air, Trace};
use noid_core::mle::split::{reconstruct_from_slices, split_mle_into_slices};
use noid_core::transcript::FiatShamir;
use noid_core::{AdditiveNTT, Block128};
use noid_fri::code::LOG_RATE;
use noid_fri::prover::{commit_fast, FriCommitment};
use noid_gkr::{
    build_auth_unified_from_inputs, build_boundary_mle, prove_auth_killshot,
    prove_spine_killshot_with_states, reconstruct_slot_states, verify_auth_killshot,
    verify_spine_killshot, AuthCircuit, AuthInputs, AuthProofKillShot, SpineCircuit, SpineInputs,
    SpineProofKillShot, N_AUTH_UNIFIED_VARS, N_BOUNDARY_VARS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_tx::PublicInputs;

use crate::{
    prove_air_with_slices, verify_air_with_slices, SliceClaim, StarkProof, VerifyError,
};

/// Base log-length for all columns (trace + slices). The AIR operates
/// at log_rows=13 and slices are cut to match.
const BASE_LOG: usize = 13;

// ---------------------------------------------------------------------------
// TxProof — the per-transaction proof bundle shipped over the wire.
// ---------------------------------------------------------------------------

/// Complete per-transaction proof. Contains everything a verifier needs
/// to confirm the state transition without access to the witness.
#[derive(Debug, Clone)]
pub struct TxProof {
    /// STARK seal over the extended trace (base AIR columns + 6 slice columns).
    pub stark: StarkProof,
    /// SpineGKR Kill-Shot proof (59-perm tx-body Merkle spine).
    pub spine: SpineProofKillShot,
    /// AuthGKR Kill-Shot proof (4x5 auth sponges).
    pub auth: AuthProofKillShot,
    /// Number of boundary-slice columns appended after the AIR columns.
    pub n_boundary_slices: usize,
}

/// Inputs required to produce a `TxProof`.
#[derive(Clone)]
pub struct TxWitness<'a> {
    pub air: &'a dyn Air,
    pub trace: &'a Trace,
    pub pi: &'a PublicInputs,
    pub spine_inputs: &'a SpineInputs,
    pub auth_inputs: &'a AuthInputs,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ProveTxError {
    TraceRejectedByAir,
    SpineHashMismatch,
}

#[derive(Debug)]
pub enum VerifyTxError {
    SpineKillShot,
    AuthKillShot,
    SliceReconstruction,
    Stark(VerifyError),
}

impl From<VerifyError> for VerifyTxError {
    fn from(e: VerifyError) -> Self {
        VerifyTxError::Stark(e)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hash_to_fields(h: &[u8; 32]) -> [Block128; 2] {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&h[..16]);
    b.copy_from_slice(&h[16..]);
    [
        Block128::from(u128::from_le_bytes(a)),
        Block128::from(u128::from_le_bytes(b)),
    ]
}

fn absorb_fri_commitment(channel: &mut Poseidon2bChannel, commitment: &FriCommitment) {
    let [h0, h1] = hash_to_fields(&commitment.vector_commitment.root);
    channel.absorb(h0);
    channel.absorb(h1);
    channel.absorb(Block128::from(commitment.vector_commitment.depth as u128));
    channel.absorb(Block128::from(commitment.packing_factor as u128));
    channel.absorb(Block128::from(commitment.log_len as u128));
}

fn reduction_to_transcript(point: &[Block128], value: Block128) -> Vec<Block128> {
    let mut out = Vec::with_capacity(point.len() + 1);
    out.extend_from_slice(point);
    out.push(value);
    out
}

fn tx_body_hash_as_lanes(pi: &PublicInputs) -> [Block128; 2] {
    pi.tx_body_hash.as_fields()
}

// ---------------------------------------------------------------------------
// prove_tx — production prover orchestrator (Stage 0: MLE Splitting)
// ---------------------------------------------------------------------------

/// Produce a `TxProof` for a validated transaction.
///
/// Single-transcript flow with uniform FRI: slices spine/auth MLEs into
/// base-length columns, commits everything at log_len=13, runs GKR,
/// then proves the STARK with slice claims injected into the multipoint
/// sumcheck.
pub fn prove_tx(witness: &TxWitness) -> Result<TxProof, ProveTxError> {
    let air = witness.air;
    let trace = witness.trace;
    let pi = witness.pi;
    let spine_inputs = witness.spine_inputs;
    let auth_inputs = witness.auth_inputs;

    #[cfg(debug_assertions)]
    if !air.check(trace) {
        return Err(ProveTxError::TraceRejectedByAir);
    }

    let claimed = tx_body_hash_as_lanes(pi);
    let spine_circuit = SpineCircuit::build();
    let auth_circuit = AuthCircuit::build();

    // =========================================================================
    // Stage 1: Build boundary MLEs and slice them
    // =========================================================================
    let spine_states = reconstruct_slot_states(&spine_circuit, spine_inputs);
    let spine_boundary_mle = build_boundary_mle(&spine_states);
    debug_assert_eq!(spine_boundary_mle.len(), 1 << N_BOUNDARY_VARS);

    let auth_unified_mle = build_auth_unified_from_inputs(&auth_circuit, auth_inputs);
    let auth_state_mle = auth_unified_mle.state;
    debug_assert_eq!(auth_state_mle.len(), 1 << N_AUTH_UNIFIED_VARS);

    // Spine: 2^15 -> 4 slices of 2^13
    let spine_slices = split_mle_into_slices(&spine_boundary_mle, N_BOUNDARY_VARS, BASE_LOG);
    debug_assert_eq!(spine_slices.len(), 4);

    // Auth: 2^14 -> 2 slices of 2^13
    let auth_slices = split_mle_into_slices(&auth_state_mle, N_AUTH_UNIFIED_VARS, BASE_LOG);
    debug_assert_eq!(auth_slices.len(), 2);

    let n_air_cols = trace.columns.len();
    let n_boundary_slices = spine_slices.len() + auth_slices.len();

    // =========================================================================
    // Stage 2: Commit extended trace (AIR columns + 6 slice columns)
    // =========================================================================
    // Pad and commit all columns at the same log_len. The slice columns
    // are already 2^13 = 2^BASE_LOG, matching the trace.
    let log_len = crate::padded_log_len(trace.log_rows);
    debug_assert_eq!(log_len, BASE_LOG);
    let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);

    let mut all_columns: Vec<Vec<Block128>> = Vec::with_capacity(n_air_cols + n_boundary_slices);
    for col in &trace.columns {
        all_columns.push(crate::pad_column(col, log_len));
    }
    for s in &spine_slices {
        all_columns.push(s.clone());
    }
    for s in &auth_slices {
        all_columns.push(s.clone());
    }

    let commitments: Vec<FriCommitment> = {
        use rayon::prelude::*;
        all_columns
            .par_iter()
            .map(|col| commit_fast(col, &ntt))
            .collect()
    };

    // =========================================================================
    // Stage 3: Seed GKR channels with slice commitments, run GKR
    // =========================================================================
    let mut spine_channel = Poseidon2bChannel::new();
    for i in 0..4 {
        absorb_fri_commitment(&mut spine_channel, &commitments[n_air_cols + i]);
    }
    let (spine_proof, spine_reductions) =
        prove_spine_killshot_with_states(&spine_states, claimed, &mut spine_channel);

    let mut auth_channel = Poseidon2bChannel::new();
    for i in 0..2 {
        absorb_fri_commitment(&mut auth_channel, &commitments[n_air_cols + 4 + i]);
    }
    let (auth_proof, auth_reductions) =
        prove_auth_killshot(&auth_circuit, auth_inputs, &mut auth_channel);

    // =========================================================================
    // Stage 4: STARK with slice claims
    // =========================================================================
    let spine_transcript =
        reduction_to_transcript(&spine_reductions.state.point, spine_reductions.state.value);
    let auth_transcript =
        reduction_to_transcript(&auth_reductions.state.point, auth_reductions.state.value);
    let mut extras_transcript = Vec::with_capacity(spine_transcript.len() + auth_transcript.len());
    extras_transcript.extend_from_slice(&spine_transcript);
    extras_transcript.extend_from_slice(&auth_transcript);

    // Split the GKR reduction points into low (BASE_LOG vars) and high.
    let r_spine = &spine_reductions.state.point;
    let r_auth = &auth_reductions.state.point;
    debug_assert_eq!(r_spine.len(), N_BOUNDARY_VARS);
    debug_assert_eq!(r_auth.len(), N_AUTH_UNIFIED_VARS);

    let spine_r_low = r_spine[..BASE_LOG].to_vec();
    let auth_r_low = r_auth[..BASE_LOG].to_vec();

    // Compute claimed slice values (prover evaluates each slice at r_low).
    let spine_slice_values: Vec<Block128> = spine_slices
        .iter()
        .map(|s| noid_core::mle::evaluate::evaluate_slice(s, &spine_r_low))
        .collect();
    let auth_slice_values: Vec<Block128> = auth_slices
        .iter()
        .map(|s| noid_core::mle::evaluate::evaluate_slice(s, &auth_r_low))
        .collect();

    // Build slice claims for the multipoint sumcheck.
    let mut slice_claims: Vec<SliceClaim> = Vec::with_capacity(n_boundary_slices);
    for (i, &val) in spine_slice_values.iter().enumerate() {
        slice_claims.push(SliceClaim {
            col_index: n_air_cols + i,
            eval_point: spine_r_low.clone(),
            value: val,
        });
    }
    for (i, &val) in auth_slice_values.iter().enumerate() {
        slice_claims.push(SliceClaim {
            col_index: n_air_cols + 4 + i,
            eval_point: auth_r_low.clone(),
            value: val,
        });
    }

    let stark = prove_air_with_slices(
        air,
        &all_columns,
        &commitments,
        pi,
        &extras_transcript,
        &slice_claims,
        log_len,
    );

    Ok(TxProof {
        stark,
        spine: spine_proof,
        auth: auth_proof,
        n_boundary_slices,
    })
}

// ---------------------------------------------------------------------------
// verify_tx — production verifier (Stage 0: MLE Splitting)
// ---------------------------------------------------------------------------

/// Verify a `TxProof` against `PublicInputs`.
///
/// Replays the single-transcript flow: commit absorption -> GKR -> STARK.
/// Reconstructs original MLE values from slice openings and checks
/// against GKR reduction values.
pub fn verify_tx(
    air: &dyn Air,
    pi: &PublicInputs,
    spine_inputs: &SpineInputs,
    auth_inputs: &AuthInputs,
    proof: &TxProof,
) -> Result<(), VerifyTxError> {
    let claimed = tx_body_hash_as_lanes(pi);
    let spine_circuit = SpineCircuit::build();
    let auth_circuit = AuthCircuit::build();

    let n_air_cols = air.n_columns();
    let n_slices = proof.n_boundary_slices;
    if n_slices != 6 {
        return Err(VerifyTxError::Stark(VerifyError::ShapeMismatch));
    }

    // =========================================================================
    // Stage 1: Verify GKR Kill-Shots (seed channels with slice commitments)
    // =========================================================================
    if proof.stark.column_commitments.len() != n_air_cols + n_slices {
        return Err(VerifyTxError::Stark(VerifyError::ShapeMismatch));
    }

    let mut spine_channel = Poseidon2bChannel::new();
    for i in 0..4 {
        absorb_fri_commitment(&mut spine_channel, &proof.stark.column_commitments[n_air_cols + i]);
    }
    let spine_reductions = verify_spine_killshot(
        &proof.spine,
        &spine_circuit,
        spine_inputs,
        claimed,
        &mut spine_channel,
    )
    .ok_or(VerifyTxError::SpineKillShot)?;

    let mut auth_channel = Poseidon2bChannel::new();
    for i in 0..2 {
        absorb_fri_commitment(
            &mut auth_channel,
            &proof.stark.column_commitments[n_air_cols + 4 + i],
        );
    }
    let auth_reductions = verify_auth_killshot(
        &proof.auth,
        &auth_circuit,
        auth_inputs,
        &mut auth_channel,
    )
    .ok_or(VerifyTxError::AuthKillShot)?;

    // =========================================================================
    // Stage 2: Verify STARK (with slice claims)
    // =========================================================================
    let spine_transcript =
        reduction_to_transcript(&spine_reductions.state.point, spine_reductions.state.value);
    let auth_transcript =
        reduction_to_transcript(&auth_reductions.state.point, auth_reductions.state.value);
    let mut extras_transcript = Vec::with_capacity(spine_transcript.len() + auth_transcript.len());
    extras_transcript.extend_from_slice(&spine_transcript);
    extras_transcript.extend_from_slice(&auth_transcript);

    let r_spine = &spine_reductions.state.point;
    let r_auth = &auth_reductions.state.point;

    let spine_r_low = r_spine[..BASE_LOG].to_vec();
    let spine_r_high = r_spine[BASE_LOG..].to_vec();
    let auth_r_low = r_auth[..BASE_LOG].to_vec();
    let auth_r_high = r_auth[BASE_LOG..].to_vec();

    // Retrieve slice openings from the STARK proof's multipoint batch.
    // These are the values of the slice columns at the multipoint
    // challenge point r''. The sumcheck + FRI guarantees their
    // correctness. We also need the claimed_values from the sumcheck
    // to reconstruct the original MLE values.
    //
    // The slice claims are embedded in the STARK verification flow.
    // After STARK verify succeeds, we reconstruct the original MLE
    // values from the slice_claimed_values and check against GKR.
    let spine_slice_values = &proof.stark.slice_claimed_values[..4];
    let auth_slice_values = &proof.stark.slice_claimed_values[4..6];

    // Reconstruct original MLE values from slices.
    let reconstructed_spine = reconstruct_from_slices(spine_slice_values, &spine_r_high);
    if reconstructed_spine != spine_reductions.state.value {
        return Err(VerifyTxError::SliceReconstruction);
    }

    let reconstructed_auth = reconstruct_from_slices(auth_slice_values, &auth_r_high);
    if reconstructed_auth != auth_reductions.state.value {
        return Err(VerifyTxError::SliceReconstruction);
    }

    // Build slice claims for STARK verification.
    let mut slice_claims: Vec<SliceClaim> = Vec::with_capacity(n_slices);
    for (i, &val) in spine_slice_values.iter().enumerate() {
        slice_claims.push(SliceClaim {
            col_index: n_air_cols + i,
            eval_point: spine_r_low.clone(),
            value: val,
        });
    }
    for (i, &val) in auth_slice_values.iter().enumerate() {
        slice_claims.push(SliceClaim {
            col_index: n_air_cols + 4 + i,
            eval_point: auth_r_low.clone(),
            value: val,
        });
    }

    verify_air_with_slices(
        air,
        pi,
        &proof.stark,
        &extras_transcript,
        &slice_claims,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Proof size
// ---------------------------------------------------------------------------

impl TxProof {
    pub fn estimated_byte_len(&self) -> usize {
        self.spine.byte_len() + self.auth.byte_len() + self.stark_estimated_bytes()
    }

    fn stark_estimated_bytes(&self) -> usize {
        let s = &self.stark;
        let n_cols = s.column_commitments.len();
        let column_roots = n_cols * 32;
        let base_openings = s.base_openings.len() * 16;
        let sumcheck: usize = s.zero_check_rounds.iter().map(|r| r.len() * 16).sum();
        let shift_partials: usize = s.shift_partials.iter().map(|p| p.len() * 16).sum();
        let multipoint: usize = s.multipoint_rounds.iter().map(|r| r.len() * 16).sum();
        let fri = s.multipoint_batch.byte_len();
        column_roots + base_openings + sumcheck + shift_partials + multipoint + fri
    }
}
