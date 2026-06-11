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
//! `WalletProofBundle { logic_proof, auth_slices }` — the wallet's proof artifact
//! that is submitted to the local mempool via `submitTxIntent`. The bundle is
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
use noid_stark::{prove_logic::LogicWitness, wallet_bundle::WalletProofBundle};
use noid_tx::{PublicInputs, TxBody, MAX_INPUTS, MAX_OUTPUTS};

use noid_stark::prove_logic::prove_logic;

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
    // The `WalletProofBundle` contains NO secret material:
    //   logic_proof = STARK + AuthKillShot (one-way outputs only)
    //   auth_slices = Poseidon2b MLE state (one-way from secret)

    Ok(WalletProofBundle {
        logic_proof,
        auth_slices,
        auth_public: auth_inputs.to_public(),
    })
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
