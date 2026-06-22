// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transaction proving inside the daemon.
//!
//! This is the ONLY place where `SpendSecret` is combined with the wallet
//! LogicProof pipeline. It NEVER leaves this function — it's passed in, used to compute
//! the auth proof, and then dropped (zeroized by `ZeroizeOnDrop` on `SpendSecret`).
//! Field-limb temporaries are wallet-local proof workspace and are not serialized.
//!
//! # What this produces
//!
//! `WalletProofBundle::{Standard4x8, Sweep25x2}` — the wallet's proof artifact
//! submitted to the local mempool via `submitTxIntent`. The bundle is
//! forwarded from the mempool to the block prover inside the daemon.
//! AuthGKR witness tables remain wallet-local; the bundle carries only public
//! auth inputs plus self-contained KillShot proof capsules embedded in logic proofs.
//!
//! # SpendSecret handling
//!
//! The secret is taken by value and zeroized when this function returns.
//! No reference escapes. No copy is serialized or stored on disk after this
//! function completes.

use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_core::Block128;
use noid_gkr::{compute_auth_boundary, AuthCircuit, AuthInputs, N_AUTH_INPUTS};
use noid_poseidon2b::primitives::SpendSecret;
use noid_stark::prove_logic::prove_logic;
use noid_stark::prove_logic::LogicWitness;
use noid_stark::prove_logic_sweep::{
    prove_sweep_logic, sweep_logic_witness_parts_from_body, SweepLogicWitness,
};
use noid_stark::wallet_bundle::{
    StandardWalletProofBundle, SweepWalletProofBundle, WalletProofBundle,
};
use noid_tx::{PublicInputs, TxBody, TxShape, MAX_INPUTS, MAX_OUTPUTS};
use zeroize::Zeroize;

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
/// `WalletProofBundle` containing the transaction logic proof and public auth inputs.
/// This bundle is submitted to the local mempool, which forwards it to
/// the block prover. SpendSecret and raw AuthGKR MLE slices NEVER appear in the bundle.
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
    spend_secret_arr.zeroize();

    // Build AIR trace (balance, range, selector constraints — public data).
    let air = TxLogicAir::new(pins);
    let logic_witness = witness_from_body(body);
    let trace = air.build_trace(&logic_witness);

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

    // SpendSecret field limbs are now only in wallet-local proof workspace.
    // The `WalletProofBundle` contains NO raw SpendSecret material and no raw
    // AuthGKR MLE slices:
    //   logic_proof = STARK + self-contained AuthKillShot capsule
    //   auth_public = public address/auth-tag boundary only

    Ok(WalletProofBundle::Standard4x8(StandardWalletProofBundle {
        logic_proof,
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

    // Sweep follows the Standard4x8 wallet artifact model: serialize only the
    // logic proof capsule plus public auth boundary, never raw AuthGKR MLE slices.
    Ok(WalletProofBundle::Sweep25x2(SweepWalletProofBundle {
        logic_proof,
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

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{derive_address, hash_auth_tag, Address, AuthTag};
    use noid_tx::{hash_tx_body_for_shape, TxInput, TxOutput};

    const TEST_LOG_SLOTS: u32 = 24;

    fn secret(seed: u8) -> SpendSecret {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_mul(37).wrapping_add(i as u8).wrapping_add(3);
        }
        SpendSecret(bytes)
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn finalize_auth_tags(body: &mut TxBody) {
        let tx_body_hash = hash_tx_body_for_shape(
            body.shape,
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        for input in body.inputs.iter_mut().filter(|i| i.valid) {
            input.auth_tag = hash_auth_tag(&input.spend_secret, &tx_body_hash);
        }
    }

    fn standard_body(spend_secret: SpendSecret) -> TxBody {
        let owner = derive_address(&spend_secret);
        let mut body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0x51; 32],
            fee: 10,
            inputs: vec![TxInput {
                slot_index: 7,
                value: 1_000,
                owner,
                spend_secret,
                auth_tag: AuthTag([0u8; 32]),
                valid: true,
            }],
            outputs: vec![TxOutput {
                slot_index: 70,
                value: 990,
                owner: Address([0xA7; 32]),
                valid: true,
            }],
            is_coinbase: false,
        };
        finalize_auth_tags(&mut body);
        body
    }

    fn sweep_body(secrets: &[SpendSecret]) -> TxBody {
        let mut inputs = Vec::with_capacity(secrets.len());
        for (i, spend_secret) in secrets.iter().cloned().enumerate() {
            inputs.push(TxInput {
                slot_index: 1_000 + i as u32,
                value: 10_000 + i as u64,
                owner: derive_address(&spend_secret),
                spend_secret,
                auth_tag: AuthTag([0u8; 32]),
                valid: true,
            });
        }
        let total: u64 = inputs.iter().map(|i| i.value).sum();
        let fee = 123u64;
        let mut body = TxBody {
            shape: TxShape::Sweep25x2,
            epoch_anchor: [0x52; 32],
            fee: fee as u128,
            inputs,
            outputs: vec![
                TxOutput {
                    slot_index: 50_000,
                    value: (total - fee) / 2,
                    owner: Address([0xB1; 32]),
                    valid: true,
                },
                TxOutput {
                    slot_index: 50_001,
                    value: total - fee - (total - fee) / 2,
                    owner: Address([0xB2; 32]),
                    valid: true,
                },
            ],
            is_coinbase: false,
        };
        finalize_auth_tags(&mut body);
        body
    }

    #[test]
    fn standard_wallet_bundle_does_not_serialize_spend_secret_bytes() {
        let spend_secret = secret(11);
        let raw_secret = spend_secret.0;
        let body = standard_body(spend_secret.clone());

        let bundle =
            prove_tx(&body, vec![spend_secret], TEST_LOG_SLOTS).expect("prove standard tx");
        let bytes = bincode::serialize(&bundle).expect("serialize wallet bundle");

        assert!(
            !contains_subslice(&bytes, &raw_secret),
            "standard wallet bundle must not contain raw spend_secret bytes"
        );
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
    fn sweep_wallet_bundle_does_not_serialize_spend_secret_bytes() {
        let secrets: Vec<_> = (0..5).map(|i| secret(21 + i)).collect();
        let raw_secrets: Vec<_> = secrets.iter().map(|s| s.0).collect();
        let body = sweep_body(&secrets);

        let bundle = prove_tx(&body, secrets, TEST_LOG_SLOTS).expect("prove sweep tx");
        let bytes = bincode::serialize(&bundle).expect("serialize wallet bundle");

        for raw_secret in raw_secrets {
            assert!(
                !contains_subslice(&bytes, &raw_secret),
                "sweep wallet bundle must not contain raw spend_secret bytes"
            );
        }
    }
}
