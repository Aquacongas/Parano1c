// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Sweep25x2 wallet-side logic proof pipeline.
//!
//! This is deliberately separate from the Standard4x8 `prove_logic` path: the
//! standard proof keeps its 4x8 AIR/GKR shape, while sweep uses its own balance
//! AIR plus dedicated 25-input AuthGKR and 142-slot tx-body SpineGKR families.

use noid_air::composition::{sweep25x2_balance_witness_from_body, Sweep25x2BalanceWitness};
use noid_air::{Air, Trace};
use noid_core::mle::split::{reconstruct_from_slices, split_mle_into_slices};
use noid_core::{Block128, TowerField};
use noid_fri_binius::COMPACT_NUM_QUERIES;
use noid_gkr::{
    build_sweep_auth_unified_from_inputs, build_sweep_spine_unified_from_inputs,
    compute_sweep_auth_boundary, compute_sweep_tx_body_hash, prove_sweep_auth_killshot_with_mle,
    prove_sweep_spine_killshot, sweep_auth_gkr_channel, verify_sweep_auth_killshot,
    verify_sweep_spine_killshot, SweepAuthCircuit, SweepAuthInputs, SweepAuthProofKillShot,
    SweepAuthPublicInputs, SweepAuthUnifiedMle, SweepSpineCircuit, SweepSpineInputs,
    SweepSpineProofKillShot, SweepSpineUnifiedMle, N_SWEEP_AUTH_INPUTS, N_SWEEP_AUTH_UNIFIED_VARS,
    N_SWEEP_SPINE_UNIFIED_VARS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::primitives::{fee_leaf, is_coinbase_leaf, tx_shape_leaf, Digest};
use noid_tx::{hash_tx_body_for_shape, PublicInputs, TxBody, TxInput, TxOutput, TxShape};

use crate::interleaved::{prove_air_interleaved, verify_air_interleaved, InterleavedStarkProof};
use crate::{SliceClaim, VerifyError};

/// Keep all interleaved columns at the same length as the standard wallet path.
const BASE_LOG: usize = noid_air::airs::tx_body_spine::SPINE_LOG_ROWS;
/// Base log-size used for every committed Sweep25x2 boundary slice.
pub const SWEEP_BOUNDARY_BASE_LOG: usize = BASE_LOG;
const N_SWEEP_AUTH_SLICES_PER_COLUMN: usize = 1 << (N_SWEEP_AUTH_UNIFIED_VARS - BASE_LOG);
/// Number of sweep AuthGKR `state` slices carried on wire, matching the
/// Standard4x8 `auth_slices` design at the larger Sweep25x2 auth hypercube.
pub const N_SWEEP_AUTH_SLICES: usize = N_SWEEP_AUTH_SLICES_PER_COLUMN;
const N_SWEEP_SPINE_SLICES_PER_COLUMN: usize = 1 << (N_SWEEP_SPINE_UNIFIED_VARS - BASE_LOG);
const N_SWEEP_AUTH_COLUMNS_COMMITTED: usize = 3; // state, s_in, s_out.
const N_SWEEP_SPINE_COLUMNS_COMMITTED: usize = 3; // state, s_in, s_out.
/// Number of wallet-derived Sweep25x2 boundary slices committed by the sweep
/// logic STARK and later consumed by the real sweep bucket aggregation path.
pub const N_SWEEP_LOGIC_BOUNDARY_SLICES: usize = N_SWEEP_AUTH_COLUMNS_COMMITTED
    * N_SWEEP_AUTH_SLICES_PER_COLUMN
    + N_SWEEP_SPINE_COLUMNS_COMMITTED * N_SWEEP_SPINE_SLICES_PER_COLUMN;

/// Wallet-produced proof for `Sweep25x2`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SweepLogicProof {
    /// STARK seal over the sweep balance AIR plus committed GKR boundary slices.
    pub stark: InterleavedStarkProof,
    /// 25-input AuthGKR Kill-Shot proof.
    pub auth: SweepAuthProofKillShot,
    /// 142-slot tx-body SpineGKR Kill-Shot proof.
    pub spine: SweepSpineProofKillShot,
    /// Number of committed boundary-slice columns.
    pub n_boundary_slices: usize,
}

/// Inputs required to produce a `SweepLogicProof`.
pub struct SweepLogicWitness<'a> {
    pub air: &'a dyn Air,
    pub trace: &'a Trace,
    pub pi: &'a PublicInputs,
    pub auth_inputs: &'a SweepAuthInputs,
    pub spine_inputs: &'a SweepSpineInputs,
}

#[derive(Debug)]
pub enum ProveSweepLogicError {
    TraceRejectedByAir,
    ShapeMismatch,
}

#[derive(Debug)]
pub enum VerifySweepLogicError {
    ShapeMismatch,
    AuthKillShot,
    SpineKillShot,
    AuthSpineBridge,
    SpineHashBridge,
    SliceReconstruction,
    Stark(VerifyError),
}

impl From<VerifyError> for VerifySweepLogicError {
    fn from(e: VerifyError) -> Self {
        VerifySweepLogicError::Stark(e)
    }
}

fn digest_to_fields(d: &Digest) -> [Block128; 2] {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&d[..16]);
    b.copy_from_slice(&d[16..]);
    [
        Block128::from(u128::from_le_bytes(a)),
        Block128::from(u128::from_le_bytes(b)),
    ]
}

fn tx_body_hash_as_lanes(pi: &PublicInputs) -> [Block128; 2] {
    pi.tx_body_hash.as_fields()
}

fn reduction_to_transcript(point: &[Block128], value: Block128, out: &mut Vec<Block128>) {
    out.extend_from_slice(point);
    out.push(value);
}

fn absorb_all_reductions_to_transcript(
    auth: &noid_gkr::SweepAuthKillShotReductions,
    spine: &noid_gkr::SweepSpineKillShotReductions,
) -> Vec<Block128> {
    let mut out = Vec::new();
    reduction_to_transcript(&auth.state.point, auth.state.value, &mut out);
    reduction_to_transcript(&auth.sin.point, auth.sin.value, &mut out);
    reduction_to_transcript(&auth.sout.point, auth.sout.value, &mut out);
    reduction_to_transcript(&spine.state.point, spine.state.value, &mut out);
    reduction_to_transcript(&spine.sin.point, spine.sin.value, &mut out);
    reduction_to_transcript(&spine.sout.point, spine.sout.value, &mut out);
    out
}

/// Build Sweep25x2 AuthGKR state slices for the wallet bundle.
///
/// This is the direct analogue of Standard4x8 `auth_slices`: only the AuthGKR
/// `state` MLE is sliced and serialized. The sweep-only `s_in`/`s_out` helper
/// columns and tx-body SpineGKR columns remain internal to `prove_sweep_logic`.
pub fn build_sweep_auth_slices(auth_inputs: &SweepAuthInputs) -> Vec<Vec<Block128>> {
    let auth_circuit = SweepAuthCircuit::build();
    let auth_mle = build_sweep_auth_unified_from_inputs(&auth_circuit, auth_inputs);
    let auth_slices = split_mle_into_slices(&auth_mle.state, N_SWEEP_AUTH_UNIFIED_VARS, BASE_LOG);
    debug_assert_eq!(auth_slices.len(), N_SWEEP_AUTH_SLICES);
    auth_slices
}

fn sweep_boundary_slices_from_mles(
    auth_mle: &SweepAuthUnifiedMle,
    spine_mle: &SweepSpineUnifiedMle,
) -> Vec<Vec<Block128>> {
    let mut boundary_slices = Vec::with_capacity(N_SWEEP_LOGIC_BOUNDARY_SLICES);

    // Canonical order inside the wallet-local sweep logic STARK:
    // 1. auth.state, 2. auth.s_in, 3. auth.s_out,
    // 4. spine.state, 5. spine.s_in, 6. spine.s_out.
    // Only auth.state is exported separately as `build_sweep_auth_slices`, matching
    // the existing Standard4x8 wire model. The additional s_in/s_out/spine columns
    // are internal helper columns for this proof.
    boundary_slices.extend(split_mle_into_slices(
        &auth_mle.state,
        N_SWEEP_AUTH_UNIFIED_VARS,
        BASE_LOG,
    ));
    boundary_slices.extend(split_mle_into_slices(
        &auth_mle.s_in,
        N_SWEEP_AUTH_UNIFIED_VARS,
        BASE_LOG,
    ));
    boundary_slices.extend(split_mle_into_slices(
        &auth_mle.s_out,
        N_SWEEP_AUTH_UNIFIED_VARS,
        BASE_LOG,
    ));
    boundary_slices.extend(split_mle_into_slices(
        &spine_mle.state,
        N_SWEEP_SPINE_UNIFIED_VARS,
        BASE_LOG,
    ));
    boundary_slices.extend(split_mle_into_slices(
        &spine_mle.s_in,
        N_SWEEP_SPINE_UNIFIED_VARS,
        BASE_LOG,
    ));
    boundary_slices.extend(split_mle_into_slices(
        &spine_mle.s_out,
        N_SWEEP_SPINE_UNIFIED_VARS,
        BASE_LOG,
    ));

    debug_assert_eq!(boundary_slices.len(), N_SWEEP_LOGIC_BOUNDARY_SLICES);
    boundary_slices
}

fn push_precomputed_boundary_slices(
    boundary_slices: &[Vec<Block128>],
    cursor: &mut usize,
    n_slices: usize,
    num_vars: usize,
    all_columns: &mut Vec<Vec<Block128>>,
    reductions_point: &[Block128],
    reductions_value: Block128,
    slice_claims: &mut Vec<SliceClaim>,
) -> Vec<Block128> {
    debug_assert_eq!(reductions_point.len(), num_vars);
    let group = &boundary_slices[*cursor..*cursor + n_slices];
    let r_low = reductions_point[..BASE_LOG].to_vec();
    let values: Vec<Block128> = group
        .iter()
        .map(|s| noid_core::mle::evaluate::evaluate_slice(s, &r_low))
        .collect();
    let reconstructed = reconstruct_from_slices(&values, &reductions_point[BASE_LOG..]);
    debug_assert_eq!(reconstructed, reductions_value);

    for (slice, &value) in group.iter().zip(values.iter()) {
        let col_index = all_columns.len();
        all_columns.push(slice.clone());
        slice_claims.push(SliceClaim {
            col_index,
            eval_point: r_low.clone(),
            value,
        });
    }
    *cursor += n_slices;
    values
}

fn reconstruct_column_reduction(
    values: &[Block128],
    point: &[Block128],
    expected: Block128,
) -> Result<(), VerifySweepLogicError> {
    let got = reconstruct_from_slices(values, &point[BASE_LOG..]);
    if got == expected {
        Ok(())
    } else {
        Err(VerifySweepLogicError::SliceReconstruction)
    }
}

fn push_verify_slice_claims(
    n_air_cols: usize,
    n_slices: usize,
    point: &[Block128],
    proof_values: &[Block128],
    cursor: &mut usize,
    slice_claims: &mut Vec<SliceClaim>,
) -> Result<(), VerifySweepLogicError> {
    let r_low = point[..BASE_LOG].to_vec();
    for _ in 0..n_slices {
        let col_index = n_air_cols + *cursor;
        let value = *proof_values
            .get(*cursor)
            .ok_or(VerifySweepLogicError::SliceReconstruction)?;
        slice_claims.push(SliceClaim {
            col_index,
            eval_point: r_low.clone(),
            value,
        });
        *cursor += 1;
    }
    Ok(())
}

/// Build canonical public sweep spine inputs from a transaction body.
pub fn sweep_spine_inputs_from_body(body: &TxBody) -> SweepSpineInputs {
    assert_eq!(
        body.shape,
        TxShape::Sweep25x2,
        "unsupported tx body shape for Sweep25x2 spine"
    );
    assert!(body.inputs.len() <= TxShape::Sweep25x2.max_inputs());
    assert!(body.outputs.len() <= TxShape::Sweep25x2.max_outputs());

    let mut input_leaves = [[Block128::ZERO; 4]; TxShape::Sweep25x2.max_inputs()];
    for i in 0..TxShape::Sweep25x2.max_inputs() {
        let inp = body.inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
        let [owner_hi, owner_lo] = inp.owner.as_fields();
        input_leaves[i] = [
            Block128::from(inp.slot_index as u128),
            Block128::from(inp.value as u128),
            owner_hi,
            owner_lo,
        ];
    }

    let mut output_leaves = [[Block128::ZERO; 4]; TxShape::Sweep25x2.max_outputs()];
    for i in 0..TxShape::Sweep25x2.max_outputs() {
        let out = body.outputs.get(i).copied().unwrap_or_else(TxOutput::dummy);
        let [owner_hi, owner_lo] = out.owner.as_fields();
        output_leaves[i] = [
            Block128::from(out.slot_index as u128),
            Block128::from(out.value as u128),
            owner_hi,
            owner_lo,
        ];
    }

    SweepSpineInputs {
        epoch_anchor: digest_to_fields(&body.epoch_anchor),
        fee_leaf: digest_to_fields(&fee_leaf(body.fee)),
        shape_leaf: digest_to_fields(&tx_shape_leaf(TxShape::Sweep25x2.id())),
        input_leaves,
        output_leaves,
        is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(body.is_coinbase)),
        pad_leaf: [Block128::ZERO, Block128::ZERO],
    }
}

/// Build sweep auth inputs from a wallet-owned body. Secrets remain private to
/// the returned witness and are never needed by verifiers.
pub fn sweep_auth_inputs_from_body(body: &TxBody) -> SweepAuthInputs {
    assert_eq!(
        body.shape,
        TxShape::Sweep25x2,
        "unsupported tx body shape for Sweep25x2 auth"
    );
    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );

    let mut spend_secret = [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS];
    for i in 0..N_SWEEP_AUTH_INPUTS {
        let inp = body.inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
        if inp.valid {
            spend_secret[i] = inp.spend_secret.as_fields();
        }
    }

    let tx_body_hash = tx_body_hash.as_fields();
    let auth_circuit = SweepAuthCircuit::build();
    let (expected_address, expected_auth_tag) =
        compute_sweep_auth_boundary(&auth_circuit, spend_secret, tx_body_hash);

    SweepAuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    }
}

/// Build the sweep balance AIR/trace, AuthGKR inputs and SpineGKR inputs from a
/// single body. This is the wallet construction entry point for tests and future
/// mempool integration.
pub fn sweep_logic_witness_parts_from_body(
    body: &TxBody,
) -> (
    noid_air::airs::Sweep25x2BalanceGateAir,
    Trace,
    SweepAuthInputs,
    SweepSpineInputs,
) {
    let balance: Sweep25x2BalanceWitness = sweep25x2_balance_witness_from_body(body);
    let (air, trace) = balance.build_air_and_trace_with_log_rows(BASE_LOG);
    let auth_inputs = sweep_auth_inputs_from_body(body);
    let spine_inputs = sweep_spine_inputs_from_body(body);
    (air, trace, auth_inputs, spine_inputs)
}

pub fn prove_sweep_logic(
    witness: &SweepLogicWitness<'_>,
) -> Result<SweepLogicProof, ProveSweepLogicError> {
    if witness.pi.shape_id != TxShape::Sweep25x2.id() {
        return Err(ProveSweepLogicError::ShapeMismatch);
    }
    if !witness.air.check(witness.trace) {
        return Err(ProveSweepLogicError::TraceRejectedByAir);
    }

    let claimed = tx_body_hash_as_lanes(witness.pi);
    if witness.auth_inputs.tx_body_hash != claimed {
        return Err(ProveSweepLogicError::ShapeMismatch);
    }

    let spine_circuit = SweepSpineCircuit::build();
    let actual_spine_hash = compute_sweep_tx_body_hash(&spine_circuit, witness.spine_inputs);
    if actual_spine_hash != claimed {
        return Err(ProveSweepLogicError::ShapeMismatch);
    }

    let auth_circuit = SweepAuthCircuit::build();
    let auth_mle = build_sweep_auth_unified_from_inputs(&auth_circuit, witness.auth_inputs);
    let spine_mle = build_sweep_spine_unified_from_inputs(&spine_circuit, witness.spine_inputs);

    let mut auth_channel = sweep_auth_gkr_channel();
    let (auth_proof, auth_reductions) = prove_sweep_auth_killshot_with_mle(
        &auth_circuit,
        witness.auth_inputs,
        &auth_mle,
        &mut auth_channel,
    );

    let mut spine_channel = Poseidon2bChannel::new();
    let (spine_proof, spine_reductions) = prove_sweep_spine_killshot(
        &spine_circuit,
        witness.spine_inputs,
        claimed,
        &mut spine_channel,
    );

    let extras_transcript =
        absorb_all_reductions_to_transcript(&auth_reductions, &spine_reductions);

    let n_air_cols = witness.trace.columns.len();
    let log_len = crate::padded_log_len(witness.trace.log_rows);
    debug_assert_eq!(log_len, BASE_LOG);

    let mut all_columns: Vec<Vec<Block128>> =
        Vec::with_capacity(n_air_cols + N_SWEEP_LOGIC_BOUNDARY_SLICES);
    for col in &witness.trace.columns {
        all_columns.push(crate::pad_column(col, log_len));
    }

    let boundary_slices = sweep_boundary_slices_from_mles(&auth_mle, &spine_mle);
    let mut boundary_cursor = 0usize;
    let mut slice_claims: Vec<SliceClaim> = Vec::with_capacity(N_SWEEP_LOGIC_BOUNDARY_SLICES);
    push_precomputed_boundary_slices(
        &boundary_slices,
        &mut boundary_cursor,
        N_SWEEP_AUTH_SLICES_PER_COLUMN,
        N_SWEEP_AUTH_UNIFIED_VARS,
        &mut all_columns,
        &auth_reductions.state.point,
        auth_reductions.state.value,
        &mut slice_claims,
    );
    push_precomputed_boundary_slices(
        &boundary_slices,
        &mut boundary_cursor,
        N_SWEEP_AUTH_SLICES_PER_COLUMN,
        N_SWEEP_AUTH_UNIFIED_VARS,
        &mut all_columns,
        &auth_reductions.sin.point,
        auth_reductions.sin.value,
        &mut slice_claims,
    );
    push_precomputed_boundary_slices(
        &boundary_slices,
        &mut boundary_cursor,
        N_SWEEP_AUTH_SLICES_PER_COLUMN,
        N_SWEEP_AUTH_UNIFIED_VARS,
        &mut all_columns,
        &auth_reductions.sout.point,
        auth_reductions.sout.value,
        &mut slice_claims,
    );
    push_precomputed_boundary_slices(
        &boundary_slices,
        &mut boundary_cursor,
        N_SWEEP_SPINE_SLICES_PER_COLUMN,
        N_SWEEP_SPINE_UNIFIED_VARS,
        &mut all_columns,
        &spine_reductions.state.point,
        spine_reductions.state.value,
        &mut slice_claims,
    );
    push_precomputed_boundary_slices(
        &boundary_slices,
        &mut boundary_cursor,
        N_SWEEP_SPINE_SLICES_PER_COLUMN,
        N_SWEEP_SPINE_UNIFIED_VARS,
        &mut all_columns,
        &spine_reductions.sin.point,
        spine_reductions.sin.value,
        &mut slice_claims,
    );
    push_precomputed_boundary_slices(
        &boundary_slices,
        &mut boundary_cursor,
        N_SWEEP_SPINE_SLICES_PER_COLUMN,
        N_SWEEP_SPINE_UNIFIED_VARS,
        &mut all_columns,
        &spine_reductions.sout.point,
        spine_reductions.sout.value,
        &mut slice_claims,
    );

    debug_assert_eq!(boundary_cursor, N_SWEEP_LOGIC_BOUNDARY_SLICES);
    debug_assert_eq!(slice_claims.len(), N_SWEEP_LOGIC_BOUNDARY_SLICES);

    let stark = prove_air_interleaved(
        witness.air,
        &all_columns,
        witness.pi,
        &extras_transcript,
        &slice_claims,
        log_len,
        None,
        COMPACT_NUM_QUERIES,
    );

    Ok(SweepLogicProof {
        stark,
        auth: auth_proof,
        spine: spine_proof,
        n_boundary_slices: slice_claims.len(),
    })
}

pub fn verify_sweep_logic(
    air: &dyn Air,
    pi: &PublicInputs,
    spine_inputs: &SweepSpineInputs,
    auth_public: &SweepAuthPublicInputs,
    proof: &SweepLogicProof,
) -> Result<(), VerifySweepLogicError> {
    if pi.shape_id != TxShape::Sweep25x2.id() {
        return Err(VerifySweepLogicError::ShapeMismatch);
    }
    if proof.n_boundary_slices != N_SWEEP_LOGIC_BOUNDARY_SLICES {
        return Err(VerifySweepLogicError::ShapeMismatch);
    }

    let claimed = tx_body_hash_as_lanes(pi);
    if auth_public.tx_body_hash != claimed {
        return Err(VerifySweepLogicError::AuthSpineBridge);
    }

    let spine_circuit = SweepSpineCircuit::build();
    if compute_sweep_tx_body_hash(&spine_circuit, spine_inputs) != claimed {
        return Err(VerifySweepLogicError::SpineHashBridge);
    }

    let auth_circuit = SweepAuthCircuit::build();
    let mut auth_ch = sweep_auth_gkr_channel();
    let auth_reductions =
        verify_sweep_auth_killshot(&proof.auth, &auth_circuit, auth_public, &mut auth_ch)
            .ok_or(VerifySweepLogicError::AuthKillShot)?;

    let mut spine_ch = Poseidon2bChannel::new();
    let spine_reductions = verify_sweep_spine_killshot(
        &proof.spine,
        &spine_circuit,
        spine_inputs,
        claimed,
        &mut spine_ch,
    )
    .ok_or(VerifySweepLogicError::SpineKillShot)?;

    let n_live = pi.n_live_inputs as usize;
    if n_live > N_SWEEP_AUTH_INPUTS {
        return Err(VerifySweepLogicError::ShapeMismatch);
    }
    for i in 0..n_live {
        let owner = [
            spine_inputs.input_leaves[i][2],
            spine_inputs.input_leaves[i][3],
        ];
        if auth_public.expected_address[i] != owner {
            return Err(VerifySweepLogicError::AuthSpineBridge);
        }
    }

    let extras_transcript =
        absorb_all_reductions_to_transcript(&auth_reductions, &spine_reductions);

    let proof_values = &proof.stark.slice_claimed_values;
    if proof_values.len() != N_SWEEP_LOGIC_BOUNDARY_SLICES {
        return Err(VerifySweepLogicError::SliceReconstruction);
    }

    let n_air_cols = air.n_columns();
    if proof.stark.commitment.n_cols != n_air_cols + N_SWEEP_LOGIC_BOUNDARY_SLICES {
        return Err(VerifySweepLogicError::ShapeMismatch);
    }

    let mut cursor = 0usize;
    let mut slice_claims: Vec<SliceClaim> = Vec::with_capacity(N_SWEEP_LOGIC_BOUNDARY_SLICES);

    reconstruct_column_reduction(
        &proof_values[cursor..cursor + N_SWEEP_AUTH_SLICES_PER_COLUMN],
        &auth_reductions.state.point,
        auth_reductions.state.value,
    )?;
    push_verify_slice_claims(
        n_air_cols,
        N_SWEEP_AUTH_SLICES_PER_COLUMN,
        &auth_reductions.state.point,
        proof_values,
        &mut cursor,
        &mut slice_claims,
    )?;
    reconstruct_column_reduction(
        &proof_values[cursor..cursor + N_SWEEP_AUTH_SLICES_PER_COLUMN],
        &auth_reductions.sin.point,
        auth_reductions.sin.value,
    )?;
    push_verify_slice_claims(
        n_air_cols,
        N_SWEEP_AUTH_SLICES_PER_COLUMN,
        &auth_reductions.sin.point,
        proof_values,
        &mut cursor,
        &mut slice_claims,
    )?;
    reconstruct_column_reduction(
        &proof_values[cursor..cursor + N_SWEEP_AUTH_SLICES_PER_COLUMN],
        &auth_reductions.sout.point,
        auth_reductions.sout.value,
    )?;
    push_verify_slice_claims(
        n_air_cols,
        N_SWEEP_AUTH_SLICES_PER_COLUMN,
        &auth_reductions.sout.point,
        proof_values,
        &mut cursor,
        &mut slice_claims,
    )?;

    for (point, value) in [
        (&spine_reductions.state.point, spine_reductions.state.value),
        (&spine_reductions.sin.point, spine_reductions.sin.value),
        (&spine_reductions.sout.point, spine_reductions.sout.value),
    ] {
        reconstruct_column_reduction(
            &proof_values[cursor..cursor + N_SWEEP_SPINE_SLICES_PER_COLUMN],
            point,
            value,
        )?;
        push_verify_slice_claims(
            n_air_cols,
            N_SWEEP_SPINE_SLICES_PER_COLUMN,
            point,
            proof_values,
            &mut cursor,
            &mut slice_claims,
        )?;
    }
    debug_assert_eq!(cursor, N_SWEEP_LOGIC_BOUNDARY_SLICES);

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

impl SweepLogicProof {
    pub fn estimated_byte_len(&self) -> usize {
        self.auth.byte_len() + self.spine.byte_len() + self.stark.byte_len()
    }
}
