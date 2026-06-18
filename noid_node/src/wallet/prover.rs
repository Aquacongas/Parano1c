// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transaction proving inside the daemon.
//!
//! This is the ONLY place where `SpendSecret` is combined with the ZK proof
//! pipeline. It NEVER leaves this function — it's passed in, used to compute
//! the auth proof, and then dropped (zeroized by `ZeroizeOnDrop` on `SpendSecret`).
//!
//! # What this produces
//!
//! `WalletProofBundle::{Standard4x8, Sweep25x2}` — the wallet's proof artifact
//! submitted to the local mempool via `submitTxIntent`. The bundle is
//! forwarded from the mempool to the block prover inside the daemon.
//!
//! # SpendSecret handling
//!
//! The secret is taken by value and zeroized when this function returns.
//! No reference escapes. No copy is stored anywhere on disk or in memory
//! after this function completes.

use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_core::mle::split::split_mle_into_slices;
use noid_core::Block128;
use noid_gkr::{
    build_auth_unified_from_inputs, compute_auth_boundary, AuthCircuit, AuthInputs, N_AUTH_INPUTS,
    N_AUTH_UNIFIED_VARS,
};
use noid_poseidon2b::primitives::SpendSecret;
use noid_stark::prove_logic::prove_logic;
use noid_stark::prove_logic::LogicWitness;
use noid_stark::prove_logic_sweep::{
    build_sweep_auth_slices, prove_sweep_logic, sweep_logic_witness_parts_from_body,
    SweepLogicWitness,
};
use noid_stark::wallet_bundle::{
    StandardWalletProofBundle, SweepWalletProofBundle, WalletProofBundle,
};
use noid_tx::{PublicInputs, TxBody, TxShape, MAX_INPUTS, MAX_OUTPUTS};

/// Error from transaction proving.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error("prove_logic failed: {0}")]
    Logic(String),
}

/// Prove a transaction inside the daemon.
///
/// # Security
///
/// `spend_secrets[i]` is the `SpendSecret` for each live input.
/// This function is the ONLY place these secrets are used after derivation.
/// They are dropped (zeroized) when the function returns.
///
/// # Returns
///
/// `WalletProofBundle` containing the `LogicProof` and `auth_slices`.
/// This bundle is submitted to the local mempool, which forwards it to
/// the block prover. SpendSecret NEVER appears in the bundle.
pub fn prove_tx(
    body: &TxBody,
    spend_secrets: Vec<SpendSecret>, // consumed and zeroized
    log_slots: u32,
) -> Result<WalletProofBundle, ProveError> {
    match body.shape {
        TxShape::Standard4x8 => prove_standard_tx(body, spend_secrets, log_slots),
        TxShape::Sweep25x2 => prove_sweep_tx(body, spend_secrets, log_slots),
    }
}

fn prove_standard_tx(
    body: &TxBody,
    spend_secrets: Vec<SpendSecret>,
    log_slots: u32,
) -> Result<WalletProofBundle, ProveError> {
    // Build boundary pins from the tx body (public computation).
    let pins = boundary_pins_from_body(body);
    let tx_body_hash = pins.tx_body_hash;

    // Build auth inputs: inject spend_secrets and compute expected addresses / auth_tags.
    let auth_circuit = AuthCircuit::build();
    let mut spend_secret_arr = [[Block128::default(); 2]; N_AUTH_INPUTS];
    for (i, secret) in spend_secrets.iter().enumerate().take(N_AUTH_INPUTS) {
        let lo = u128::from_le_bytes(secret.0[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(secret.0[16..].try_into().unwrap());
        spend_secret_arr[i] = [noid_core::Block128::from(lo), noid_core::Block128::from(hi)];
    }

    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&auth_circuit, spend_secret_arr, tx_body_hash);

    let auth_inputs = AuthInputs {
        spend_secret: spend_secret_arr,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    };

    // Build AIR trace (balance, range, selector constraints — public data).
    let air = TxLogicAir::new(pins);
    let logic_witness = witness_from_body(body);
    let trace = air.build_trace(&logic_witness);

    // Build auth MLE and auth_slices (requires spend_secret internally).
    use noid_block::BLOCK_BASE_LOG;
    let auth_mle = build_auth_unified_from_inputs(&auth_circuit, &auth_inputs);
    let auth_slices = split_mle_into_slices(&auth_mle.state, N_AUTH_UNIFIED_VARS, BLOCK_BASE_LOG);

    // Build public inputs.
    let pi = build_public_inputs(body, log_slots);

    // Prove the logic (STARK + AuthGKR Kill-Shot).
    // This uses spend_secret internally via auth_inputs.
    let witness = LogicWitness {
        air: &air,
        trace: &trace,
        pi: &pi,
        auth_inputs: &auth_inputs,
    };
    let logic_proof = prove_logic(&witness).map_err(|e| ProveError::Logic(format!("{e:?}")))?;

    // SpendSecret is now only in `auth_inputs` and `spend_secret_arr` which
    // are stack-allocated and will be dropped (zeroized) at the end of this fn.
    // The `WalletProofBundle` contains NO raw SpendSecret material:
    //   logic_proof = STARK + AuthKillShot
    //   auth_slices = AuthGKR state slices, matching the SC-5 one-wayness model

    Ok(WalletProofBundle::Standard4x8(StandardWalletProofBundle {
        logic_proof,
        auth_slices,
        auth_public: auth_inputs.to_public(),
    }))
}

fn prove_sweep_tx(
    body: &TxBody,
    spend_secrets: Vec<SpendSecret>,
    log_slots: u32,
) -> Result<WalletProofBundle, ProveError> {
    let mut body_with_secrets = body.clone();
    let mut secret_iter = spend_secrets.into_iter();
    for input in body_with_secrets.inputs.iter_mut().filter(|i| i.valid) {
        if let Some(secret) = secret_iter.next() {
            input.spend_secret = secret;
        }
    }

    let (air, trace, auth_inputs, _) = sweep_logic_witness_parts_from_body(&body_with_secrets);
    let pi = build_public_inputs_for_shape(&body_with_secrets, log_slots);
    let witness = SweepLogicWitness {
        air: &air,
        trace: &trace,
        pi: &pi,
        auth_inputs: &auth_inputs,
    };
    let logic_proof =
        prove_sweep_logic(&witness).map_err(|e| ProveError::Logic(format!("{e:?}")))?;

    // Sweep follows the Standard4x8 wallet artifact model: serialize only
    // AuthGKR `state` slices, not s_in/s_out or tx-body SpineGKR helper columns.
    let auth_slices = build_sweep_auth_slices(&auth_inputs);

    Ok(WalletProofBundle::Sweep25x2(SweepWalletProofBundle {
        logic_proof,
        auth_slices,
        auth_public: auth_inputs.to_public(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_public_inputs(body: &TxBody, log_slots: u32) -> PublicInputs {
    use noid_tx::compute_claims_commitment;

    let pins = boundary_pins_from_body(body);
    let [lo, hi] = pins.tx_body_hash;

    let mut hash_bytes = [0u8; 32];
    hash_bytes[..16].copy_from_slice(&lo.to_u128().to_le_bytes());
    hash_bytes[16..].copy_from_slice(&hi.to_u128().to_le_bytes());

    let n_live_inputs = body.inputs.iter().filter(|i| i.valid).count() as u8;
    let n_live_outputs = body.outputs.iter().filter(|o| o.valid).count() as u8;
    let claims = compute_claims_commitment(&body.inputs, &body.outputs);

    let mut is_activation = [false; MAX_OUTPUTS];
    let mut is_deactivation = [false; MAX_INPUTS];
    for (j, out) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
        is_activation[j] = out.valid;
    }
    for (i, inp) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
        is_deactivation[i] = inp.valid;
    }

    PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash: noid_poseidon2b::primitives::TxBodyHash(hash_bytes),
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs,
        n_live_outputs,
        coinbase_credit: 0,
        log_slots, // from block header at inclusion time
        claims_commitment: claims,
        is_activation,
        is_deactivation,
    }
}

fn build_public_inputs_for_shape(body: &TxBody, log_slots: u32) -> PublicInputs {
    use noid_tx::{compute_claims_commitment, hash_tx_body_for_shape};

    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    let n_live_inputs = body.inputs.iter().filter(|i| i.valid).count() as u8;
    let n_live_outputs = body.outputs.iter().filter(|o| o.valid).count() as u8;
    let claims = compute_claims_commitment(&body.inputs, &body.outputs);

    let mut is_activation = [false; MAX_OUTPUTS];
    let mut is_deactivation = [false; MAX_INPUTS];
    if body.shape == TxShape::Standard4x8 {
        for (j, out) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
            is_activation[j] = out.valid;
        }
        for (i, inp) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
            is_deactivation[i] = inp.valid;
        }
    }

    PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash,
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs,
        n_live_outputs,
        coinbase_credit: 0,
        log_slots,
        claims_commitment: claims,
        is_activation,
        is_deactivation,
    }
}
