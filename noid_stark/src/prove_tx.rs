// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Production orchestrator: `prove_tx` / `verify_tx`.
//!
//! FRI-Binius interleaved PCS path. Single-transcript, single Merkle tree:
//!
//! 1. Seed one `Poseidon2bChannel` with `PublicInputs`.
//! 2. Build Spine boundary MLE (2^15); slice into 4 columns of 2^13.
//! 3. Build Auth boundary MLE (2^14); slice into 2 columns of 2^13.
//! 4. Append all 6 slice columns to the trace. Commit all columns
//!    into ONE interleaved Merkle tree (FRI-Binius PCS).
//! 5. Absorb interleaved Merkle cap into GKR channels.
//! 6. Run SpineGKR Kill-Shot, then AuthGKR Kill-Shot.
//! 7. Thread both `(r_B, v_B)` reductions into STARK `extra_transcript`.
//! 8. STARK prove: zero-check + multipoint close (with slice claims) +
//!    single FRI-Binius mixed opening for all 297 columns.
//!
//! The verifier replays in the same order, reconstructs the original
//! MLE values from slice openings via `reconstruct_from_slices`, and
//! checks against the GKR reduction values.

use noid_air::{Air, Trace};
use noid_core::mle::split::{reconstruct_from_slices, split_mle_into_slices};
use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_fri_binius::MerkleCap;
use noid_gkr::{
    auth_gkr_channel, build_auth_unified_from_inputs, build_boundary_mle, prove_auth_killshot,
    prove_spine_killshot_with_states, reconstruct_slot_states, verify_auth_killshot,
    verify_spine_killshot, AuthCircuit, AuthInputs, AuthProofKillShot, AuthPublicInputs,
    SpineCircuit, SpineInputs, SpineProofKillShot, N_AUTH_UNIFIED_VARS, N_BOUNDARY_VARS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_tx::PublicInputs;
use rayon;

use crate::interleaved::{prove_air_interleaved, verify_air_interleaved, InterleavedStarkProof};
use crate::{SliceClaim, VerifyError};

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
    pub stark: InterleavedStarkProof,
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
    AuthSpineBridge,
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

/// Absorb the interleaved Merkle cap into a GKR Poseidon2b channel.
fn absorb_merkle_cap(channel: &mut Poseidon2bChannel, cap: &MerkleCap) {
    for hash in &cap.hashes {
        let [h0, h1] = hash_to_fields(hash);
        channel.absorb(h0);
        channel.absorb(h1);
    }
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
// prove_tx — production prover orchestrator (FRI-Binius Interleaved PCS)
// ---------------------------------------------------------------------------

/// Produce a `TxProof` for a validated transaction.
///
/// Single-transcript flow with FRI-Binius interleaved commitment:
/// slices spine/auth MLEs into base-length columns, commits everything
/// into ONE interleaved Merkle tree, runs GKR, then proves the STARK
/// with slice claims injected into the multipoint sumcheck.
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
    // Stage 2: Build extended column set (AIR + 6 slices)
    // =========================================================================
    let log_len = crate::padded_log_len(trace.log_rows);
    debug_assert_eq!(log_len, BASE_LOG);

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

    // =========================================================================
    // Stage 3: Interleaved commit + GKR (absorb cap into GKR channels)
    // =========================================================================
    // Commit once and reuse: the prover state is passed to
    // prove_air_interleaved so it skips the redundant second commit.
    let ntt = noid_core::AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = noid_fri::hasher::Blake3Hasher::new();
    let col_refs: Vec<&[Block128]> = all_columns.iter().map(|c| c.as_slice()).collect();
    let (pre_commitment, pre_state) = noid_fri_binius::interleaved_commit(&col_refs, &ntt, &hasher);
    let cap = &pre_commitment.cap;

    // SpineGKR seeds from Merkle cap (binds to committed columns).
    // AuthGKR uses a deterministic self-seeded channel (no cap dependency)
    // so the same proof can be reused in block context without re-proving.
    let ((spine_proof, spine_reductions), (auth_proof, auth_reductions)) = rayon::join(
        || {
            let mut spine_channel = Poseidon2bChannel::new();
            absorb_merkle_cap(&mut spine_channel, cap);
            prove_spine_killshot_with_states(&spine_states, claimed, &mut spine_channel)
        },
        || {
            let mut auth_channel = auth_gkr_channel();
            prove_auth_killshot(&auth_circuit, auth_inputs, &mut auth_channel)
        },
    );

    // =========================================================================
    // Stage 4: STARK with slice claims (FRI-Binius interleaved path)
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

    let stark = prove_air_interleaved(
        air,
        &all_columns,
        pi,
        &extras_transcript,
        &slice_claims,
        log_len,
        Some((pre_commitment, pre_state)),
        noid_fri_binius::COMPACT_NUM_QUERIES,
    );

    Ok(TxProof {
        stark,
        spine: spine_proof,
        auth: auth_proof,
        n_boundary_slices,
    })
}

// ---------------------------------------------------------------------------
// verify_tx — production verifier (FRI-Binius Interleaved PCS)
// ---------------------------------------------------------------------------

/// Verify a `TxProof` against `PublicInputs`.
///
/// Replays the single-transcript flow: cap absorption -> GKR -> STARK.
/// Reconstructs original MLE values from slice openings and checks
/// against GKR reduction values.
pub fn verify_tx(
    air: &dyn Air,
    pi: &PublicInputs,
    spine_inputs: &SpineInputs,
    auth_public: &AuthPublicInputs,
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
    // Stage 1: Verify GKR Kill-Shots (seed channels with Merkle cap)
    // =========================================================================
    if proof.stark.commitment.n_cols != n_air_cols + n_slices {
        return Err(VerifyTxError::Stark(VerifyError::ShapeMismatch));
    }
    let cap = &proof.stark.commitment.cap;

    let (spine_result, auth_result) = rayon::join(
        || {
            let mut ch = Poseidon2bChannel::new();
            absorb_merkle_cap(&mut ch, cap);
            verify_spine_killshot(&proof.spine, &spine_circuit, spine_inputs, claimed, &mut ch)
        },
        || {
            let mut ch = auth_gkr_channel();
            verify_auth_killshot(&proof.auth, &auth_circuit, auth_public, &mut ch)
        },
    );
    let spine_reductions = spine_result.ok_or(VerifyTxError::SpineKillShot)?;
    let auth_reductions = auth_result.ok_or(VerifyTxError::AuthKillShot)?;

    // =========================================================================
    // Stage 1b: Auth <-> Spine bridge
    // =========================================================================
    if auth_public.tx_body_hash != claimed {
        return Err(VerifyTxError::AuthSpineBridge);
    }
    let n_live = pi.n_live_inputs as usize;
    for i in 0..n_live {
        let owner_hi = spine_inputs.input_leaves[i][2];
        let owner_lo = spine_inputs.input_leaves[i][3];
        if auth_public.expected_address[i] != [owner_hi, owner_lo] {
            return Err(VerifyTxError::AuthSpineBridge);
        }
    }

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

    // Retrieve slice openings from the mixed opening proof.
    // The first n_total entries in all_openings are column evaluations at r''.
    // But we need the slice_claimed_values for reconstruction, which are
    // stored separately in the proof.
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

    verify_air_interleaved(air, pi, &proof.stark, &extras_transcript, &slice_claims, noid_fri_binius::COMPACT_NUM_QUERIES)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Proof size
// ---------------------------------------------------------------------------

impl TxProof {
    pub fn estimated_byte_len(&self) -> usize {
        self.spine.byte_len() + self.auth.byte_len() + self.stark.byte_len()
    }
}
