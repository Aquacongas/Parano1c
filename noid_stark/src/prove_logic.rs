// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Stateless logic proof pipeline: `prove_logic` / `verify_logic`.
//!
//! This is the wallet-side proving path in the Split GKR architecture.
//! The wallet produces a `LogicProof` that demonstrates:
//! - UTXO conservation (balance constraints)
//! - Auth-tag validity (GKR auth Kill-Shot)
//! - Value/selector domain constraints
//!
//! SpineGKR (body-hash correctness from leaves) is NOT proven here —
//! it is deferred to the block prover who generates it from public
//! SpineInputs. The wallet only proves ownership (AuthGKR) which
//! requires the spend_secret.
//!
//! The `LogicProof` does NOT bind to any specific on-chain state root.
//! It binds to an `epoch_anchor` (hash of a recent block header) which
//! gives the proof a ~6-block TTL without requiring re-proving when
//! new blocks arrive. State binding is performed at block level by the
//! miner's `BlockStateBinding` proof.
//!
//! Pipeline:
//! 1. Build `TxLogicAir` trace from `LogicWitness`
//! 2. Slice auth boundary MLE into base-length columns
//! 3. Interleaved commit (AIR cols + N_AUTH_SLICES auth slice cols, one Merkle tree)
//! 4. AuthGKR Kill-Shot (deterministic self-seeded channel)
//! 5. STARK zero-check over `TxLogicAir` with auth slice claims

use noid_air::composition::tx_logic::TxLogicAir;
use noid_air::{Air, Trace};
use noid_core::mle::split::{reconstruct_from_slices, split_mle_into_slices};
use noid_core::Block128;
use noid_gkr::{
    auth_gkr_channel, build_auth_unified_from_inputs, prove_auth_killshot_with_mle,
    verify_auth_killshot, AuthCircuit, AuthInputs, AuthProofKillShot, AuthPublicInputs,
    SpineInputs, N_AUTH_UNIFIED_VARS,
};
use noid_tx::PublicInputs;

use crate::interleaved::{prove_air_interleaved, verify_air_interleaved, InterleavedStarkProof};
use crate::{SliceClaim, VerifyError};

use noid_air::airs::tx_body_spine::SPINE_LOG_ROWS;
use noid_fri_binius::COMPACT_NUM_QUERIES;

/// Auth-MLE slice granularity: must equal `SPINE_LOG_ROWS` so that
/// every column in the interleaved commit has the same length
/// `2^BASE_LOG`. With `SPINE_LOG_ROWS = 11` this gives
/// `N_AUTH_UNIFIED_SLICES = 2^(14-11) = 8` slices per proof.
const BASE_LOG: usize = SPINE_LOG_ROWS;

/// Number of auth-MLE boundary slices committed per LogicProof.
/// = 2^(N_AUTH_UNIFIED_VARS - BASE_LOG) = 2^(14 - 11) = 8.
const N_AUTH_SLICES: usize = 1 << (N_AUTH_UNIFIED_VARS - BASE_LOG);

// ---------------------------------------------------------------------------
// LogicProof — the wallet-produced proof bundle
// ---------------------------------------------------------------------------

/// Stateless logic proof produced by the wallet. Contains everything
/// needed to verify transaction logic without on-chain state access.
///
/// Split GKR: only AuthGKR is included. SpineGKR is deferred to the
/// block prover who generates it from public SpineInputs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogicProof {
    /// STARK seal over the TxLogicAir trace + 2 auth boundary-slice columns.
    pub stark: InterleavedStarkProof,
    /// AuthGKR Kill-Shot proof (4x5 auth sponges).
    pub auth: AuthProofKillShot,
    /// Number of boundary-slice columns: `N_AUTH_SLICES` auth slices.
    /// With BASE_LOG=11 this is 8 (was 2 at BASE_LOG=13).
    pub n_boundary_slices: usize,
}

/// Inputs required to produce a `LogicProof`.
///
/// Split GKR: no `SpineInputs` needed — spine is proven at block level.
#[derive(Clone)]
pub struct LogicWitness<'a> {
    pub air: &'a TxLogicAir,
    pub trace: &'a Trace,
    pub pi: &'a PublicInputs,
    pub auth_inputs: &'a AuthInputs,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ProveLogicError {
    TraceRejectedByAir,
}

#[derive(Debug)]
pub enum VerifyLogicError {
    AuthKillShot,
    AuthSpineBridge,
    SliceReconstruction,
    Stark(VerifyError),
}

impl From<VerifyError> for VerifyLogicError {
    fn from(e: VerifyError) -> Self {
        VerifyLogicError::Stark(e)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
// prove_logic
// ---------------------------------------------------------------------------

/// Produce a `LogicProof` for a validated transaction.
///
/// Split GKR: the wallet proves AuthGKR + STARK only. SpineGKR is
/// deferred to the block prover. The proof binds to `epoch_anchor`
/// and `claims_commitment` via the Fiat-Shamir channel.
pub fn prove_logic(witness: &LogicWitness) -> Result<LogicProof, ProveLogicError> {
    let air = witness.air;
    let trace = witness.trace;
    let pi = witness.pi;
    let auth_inputs = witness.auth_inputs;

    #[cfg(debug_assertions)]
    if !air.check(trace) {
        return Err(ProveLogicError::TraceRejectedByAir);
    }

    let auth_circuit = AuthCircuit::build();

    // Build auth boundary MLE and slice it
    let auth_unified_mle = build_auth_unified_from_inputs(&auth_circuit, auth_inputs);
    debug_assert_eq!(auth_unified_mle.state.len(), 1 << N_AUTH_UNIFIED_VARS);

    let auth_slices = split_mle_into_slices(&auth_unified_mle.state, N_AUTH_UNIFIED_VARS, BASE_LOG);
    debug_assert_eq!(auth_slices.len(), N_AUTH_SLICES);

    let n_air_cols = trace.columns.len();
    let n_boundary_slices = auth_slices.len();

    // Build extended column set (AIR + N_AUTH_SLICES auth slices)
    let log_len = crate::padded_log_len(trace.log_rows);
    debug_assert_eq!(log_len, BASE_LOG);

    let mut all_columns: Vec<Vec<Block128>> = Vec::with_capacity(n_air_cols + n_boundary_slices);
    for col in &trace.columns {
        all_columns.push(crate::pad_column(col, log_len));
    }
    for s in &auth_slices {
        all_columns.push(s.clone());
    }

    // Interleaved commit + AuthGKR
    let ntt = noid_core::AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = noid_poseidon2b::native::compression::Poseidon2bSponge::new();
    let col_refs: Vec<&[Block128]> = all_columns.iter().map(|c| c.as_slice()).collect();
    let (pre_commitment, pre_state) = noid_fri_binius::interleaved_commit(&col_refs, &ntt, &hasher);

    let mut auth_channel = auth_gkr_channel();
    let (auth_proof, auth_reductions) = prove_auth_killshot_with_mle(
        &auth_circuit,
        auth_inputs,
        &auth_unified_mle,
        &mut auth_channel,
    );

    // STARK with auth slice claims only
    let extras_transcript =
        reduction_to_transcript(&auth_reductions.state.point, auth_reductions.state.value);

    let r_auth = &auth_reductions.state.point;
    debug_assert_eq!(r_auth.len(), N_AUTH_UNIFIED_VARS);

    let auth_r_low = r_auth[..BASE_LOG].to_vec();

    let auth_slice_values: Vec<Block128> = auth_slices
        .iter()
        .map(|s| noid_core::mle::evaluate::evaluate_slice(s, &auth_r_low))
        .collect();

    let mut slice_claims: Vec<SliceClaim> = Vec::with_capacity(n_boundary_slices);
    for (i, &val) in auth_slice_values.iter().enumerate() {
        slice_claims.push(SliceClaim {
            col_index: n_air_cols + i,
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
        COMPACT_NUM_QUERIES,
    );

    Ok(LogicProof {
        stark,
        auth: auth_proof,
        n_boundary_slices,
    })
}

// ---------------------------------------------------------------------------
// verify_logic
// ---------------------------------------------------------------------------

/// Verify a `LogicProof` against `PublicInputs`.
///
/// Split GKR: only verifies AuthGKR + STARK. SpineGKR is not part of
/// the wallet proof — body-hash correctness from leaves is verified
/// at block level.
///
/// The bridge check ensures `auth_public.tx_body_hash` matches the
/// `PublicInputs.tx_body_hash`, and that auth addresses match the
/// spine inputs (owner fields). This confirms the wallet proved
/// ownership of the correct inputs.
///
/// PRIVACY: Accepts `AuthPublicInputs` — the verifier never sees
/// `spend_secret`.
pub fn verify_logic(
    air: &dyn Air,
    pi: &PublicInputs,
    spine_inputs: &SpineInputs,
    auth_public: &AuthPublicInputs,
    proof: &LogicProof,
) -> Result<(), VerifyLogicError> {
    let claimed = tx_body_hash_as_lanes(pi);
    let auth_circuit = AuthCircuit::build();

    let n_air_cols = air.n_columns();
    let n_slices = proof.n_boundary_slices;
    if n_slices != N_AUTH_SLICES {
        return Err(VerifyLogicError::Stark(VerifyError::ShapeMismatch));
    }

    // Verify AuthGKR Kill-Shot
    if proof.stark.commitment.n_cols != n_air_cols + n_slices {
        return Err(VerifyLogicError::Stark(VerifyError::ShapeMismatch));
    }

    let mut ch = auth_gkr_channel();
    let auth_reductions = verify_auth_killshot(&proof.auth, &auth_circuit, auth_public, &mut ch)
        .ok_or(VerifyLogicError::AuthKillShot)?;

    // Auth <-> Spine bridge: tx_body_hash must agree unconditionally.
    if auth_public.tx_body_hash != claimed {
        return Err(VerifyLogicError::AuthSpineBridge);
    }
    // Address check: only live inputs (deactivating slots).
    let n_live = pi.n_live_inputs as usize;
    for i in 0..n_live {
        let owner_hi = spine_inputs.input_leaves[i][2];
        let owner_lo = spine_inputs.input_leaves[i][3];
        if auth_public.expected_address[i] != [owner_hi, owner_lo] {
            return Err(VerifyLogicError::AuthSpineBridge);
        }
    }

    // Verify STARK with auth slice claims
    let extras_transcript =
        reduction_to_transcript(&auth_reductions.state.point, auth_reductions.state.value);

    let r_auth = &auth_reductions.state.point;
    let auth_r_low = r_auth[..BASE_LOG].to_vec();
    let auth_r_high = r_auth[BASE_LOG..].to_vec();

    let auth_slice_values = &proof.stark.slice_claimed_values[..n_slices];

    let reconstructed_auth = reconstruct_from_slices(auth_slice_values, &auth_r_high);
    if reconstructed_auth != auth_reductions.state.value {
        return Err(VerifyLogicError::SliceReconstruction);
    }

    let mut slice_claims: Vec<SliceClaim> = Vec::with_capacity(n_slices);
    for (i, &val) in auth_slice_values.iter().enumerate() {
        slice_claims.push(SliceClaim {
            col_index: n_air_cols + i,
            eval_point: auth_r_low.clone(),
            value: val,
        });
    }

    verify_air_interleaved(
        air,
        pi,
        &proof.stark,
        &extras_transcript,
        &slice_claims,
        COMPACT_NUM_QUERIES,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Proof size
// ---------------------------------------------------------------------------

impl LogicProof {
    pub fn estimated_byte_len(&self) -> usize {
        self.auth.byte_len() + self.stark.byte_len()
    }
}
