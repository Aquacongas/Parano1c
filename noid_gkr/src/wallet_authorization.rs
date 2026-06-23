// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Auth-only wallet authorization artifact.

use bincode::Options;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::primitives::SpendSecret;
use noid_tx::{validate_public_tx_logic, PublicLogicError, TxBody, TxShape};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::auth_statement::{
    standard_auth_public_from_body, sweep_auth_public_from_body, AuthStatementError,
};
use crate::{
    auth_gkr_channel, compute_auth_boundary, compute_sweep_auth_boundary, prove_auth_killshot,
    prove_sweep_auth_killshot, sweep_auth_gkr_channel, verify_auth_killshot,
    verify_sweep_auth_killshot, AuthCircuit, AuthInputs, AuthProofKillShot, SweepAuthCircuit,
    SweepAuthInputs, SweepAuthProofKillShot, N_AUTH_INPUTS, N_SWEEP_AUTH_INPUTS,
};

pub const MAX_STANDARD_AUTHORIZATION_BYTES: usize = 192 * 1024;
pub const MAX_SWEEP_AUTHORIZATION_BYTES: usize = 256 * 1024;
pub const MAX_AUTHORIZATION_BUNDLE_BYTES: usize = MAX_SWEEP_AUTHORIZATION_BYTES;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletAuthorizationBundle {
    Standard4x8(AuthProofKillShot),
    Sweep25x2(SweepAuthProofKillShot),
}

impl WalletAuthorizationBundle {
    pub fn shape(&self) -> TxShape {
        match self {
            Self::Standard4x8(_) => TxShape::Standard4x8,
            Self::Sweep25x2(_) => TxShape::Sweep25x2,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AuthorizationEncodeError> {
        bincode_options()
            .serialize(self)
            .map_err(|e| AuthorizationEncodeError::Bincode(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthorizationDecodeError> {
        if bytes.len() > MAX_AUTHORIZATION_BUNDLE_BYTES {
            return Err(AuthorizationDecodeError::TooLarge {
                actual: bytes.len(),
                max: MAX_AUTHORIZATION_BUNDLE_BYTES,
            });
        }
        bincode_options()
            .deserialize(bytes)
            .map_err(|e| AuthorizationDecodeError::Bincode(e.to_string()))
    }

    pub fn from_bytes_for_shape(
        bytes: &[u8],
        shape: TxShape,
    ) -> Result<Self, AuthorizationDecodeError> {
        let max = max_authorization_bytes_for_shape(shape);
        if bytes.len() > max {
            return Err(AuthorizationDecodeError::TooLarge {
                actual: bytes.len(),
                max,
            });
        }
        let bundle = Self::from_bytes(bytes)?;
        if bundle.shape() != shape {
            return Err(AuthorizationDecodeError::ShapeMismatch {
                expected: shape,
                actual: bundle.shape(),
            });
        }
        Ok(bundle)
    }

    pub fn byte_len(&self) -> Result<usize, AuthorizationEncodeError> {
        self.to_bytes().map(|bytes| bytes.len())
    }
}

pub const fn max_authorization_bytes_for_shape(shape: TxShape) -> usize {
    match shape {
        TxShape::Standard4x8 => MAX_STANDARD_AUTHORIZATION_BYTES,
        TxShape::Sweep25x2 => MAX_SWEEP_AUTHORIZATION_BYTES,
    }
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_AUTHORIZATION_BUNDLE_BYTES as u64)
        .reject_trailing_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationEncodeError {
    Bincode(String),
}

impl std::fmt::Display for AuthorizationEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AuthorizationEncodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecodeError {
    TooLarge { actual: usize, max: usize },
    ShapeMismatch { expected: TxShape, actual: TxShape },
    Bincode(String),
}

impl std::fmt::Display for AuthorizationDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AuthorizationDecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveAuthorizationError {
    PublicLogic(PublicLogicError),
    ShapeMismatch {
        expected: TxShape,
        actual: TxShape,
    },
    SecretCount {
        expected: usize,
        actual: usize,
    },
    BoundaryMismatch {
        input_index: usize,
        field: &'static str,
    },
}

impl From<PublicLogicError> for ProveAuthorizationError {
    fn from(value: PublicLogicError) -> Self {
        Self::PublicLogic(value)
    }
}

impl std::fmt::Display for ProveAuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProveAuthorizationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyAuthorizationError {
    PublicLogic(PublicLogicError),
    AuthStatement(AuthStatementError),
    ShapeMismatch { expected: TxShape, actual: TxShape },
    AuthProof,
}

impl From<PublicLogicError> for VerifyAuthorizationError {
    fn from(value: PublicLogicError) -> Self {
        Self::PublicLogic(value)
    }
}

impl From<AuthStatementError> for VerifyAuthorizationError {
    fn from(value: AuthStatementError) -> Self {
        Self::AuthStatement(value)
    }
}

impl std::fmt::Display for VerifyAuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VerifyAuthorizationError {}

pub fn prove_wallet_authorization(
    body: &TxBody,
    spend_secrets: Vec<SpendSecret>,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    validate_public_tx_logic(body)?;
    match body.shape {
        TxShape::Standard4x8 => prove_standard_authorization(body, spend_secrets),
        TxShape::Sweep25x2 => prove_sweep_authorization(body, spend_secrets),
    }
}

pub fn verify_wallet_authorization(
    body: &TxBody,
    bundle: &WalletAuthorizationBundle,
) -> Result<(), VerifyAuthorizationError> {
    validate_public_tx_logic(body)?;
    if bundle.shape() != body.shape {
        return Err(VerifyAuthorizationError::ShapeMismatch {
            expected: body.shape,
            actual: bundle.shape(),
        });
    }

    match bundle {
        WalletAuthorizationBundle::Standard4x8(proof) => {
            let public = standard_auth_public_from_body(body)?;
            let circuit = AuthCircuit::build();
            let mut channel = auth_gkr_channel();
            verify_auth_killshot(proof, &circuit, &public, &mut channel)
                .ok_or(VerifyAuthorizationError::AuthProof)?;
        }
        WalletAuthorizationBundle::Sweep25x2(proof) => {
            let public = sweep_auth_public_from_body(body)?;
            let circuit = SweepAuthCircuit::build();
            let mut channel = sweep_auth_gkr_channel();
            verify_sweep_auth_killshot(proof, &circuit, &public, &mut channel)
                .ok_or(VerifyAuthorizationError::AuthProof)?;
        }
    }
    Ok(())
}

fn prove_standard_authorization(
    body: &TxBody,
    spend_secrets: Vec<SpendSecret>,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    if body.shape != TxShape::Standard4x8 {
        return Err(ProveAuthorizationError::ShapeMismatch {
            expected: TxShape::Standard4x8,
            actual: body.shape,
        });
    }
    let facts = validate_public_tx_logic(body)?;
    let live_positions: Vec<usize> = body
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(i, input)| input.valid.then_some(i))
        .collect();
    if spend_secrets.len() != live_positions.len() {
        return Err(ProveAuthorizationError::SecretCount {
            expected: live_positions.len(),
            actual: spend_secrets.len(),
        });
    }

    let mut secret_fields = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for (position, secret) in live_positions.iter().copied().zip(spend_secrets.iter()) {
        secret_fields[position] = secret.as_fields();
    }

    let circuit = AuthCircuit::build();
    let tx_body_hash = facts.tx_body_hash.as_fields();
    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, secret_fields, tx_body_hash);

    for position in live_positions {
        let input = &body.inputs[position];
        if expected_address[position] != input.owner.as_fields() {
            secret_fields.zeroize();
            return Err(ProveAuthorizationError::BoundaryMismatch {
                input_index: position,
                field: "owner",
            });
        }
        if expected_auth_tag[position] != input.auth_tag.as_fields() {
            secret_fields.zeroize();
            return Err(ProveAuthorizationError::BoundaryMismatch {
                input_index: position,
                field: "auth_tag",
            });
        }
    }

    let auth_inputs = AuthInputs {
        spend_secret: secret_fields,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    };
    secret_fields.zeroize();
    let mut channel = auth_gkr_channel();
    let (proof, _) = prove_auth_killshot(&circuit, &auth_inputs, &mut channel);
    Ok(WalletAuthorizationBundle::Standard4x8(proof))
}

fn prove_sweep_authorization(
    body: &TxBody,
    spend_secrets: Vec<SpendSecret>,
) -> Result<WalletAuthorizationBundle, ProveAuthorizationError> {
    if body.shape != TxShape::Sweep25x2 {
        return Err(ProveAuthorizationError::ShapeMismatch {
            expected: TxShape::Sweep25x2,
            actual: body.shape,
        });
    }
    let facts = validate_public_tx_logic(body)?;
    let live_positions: Vec<usize> = body
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(i, input)| input.valid.then_some(i))
        .collect();
    if spend_secrets.len() != live_positions.len() {
        return Err(ProveAuthorizationError::SecretCount {
            expected: live_positions.len(),
            actual: spend_secrets.len(),
        });
    }

    let mut secret_fields = [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS];
    for (position, secret) in live_positions.iter().copied().zip(spend_secrets.iter()) {
        secret_fields[position] = secret.as_fields();
    }

    let circuit = SweepAuthCircuit::build();
    let tx_body_hash = facts.tx_body_hash.as_fields();
    let (expected_address, expected_auth_tag) =
        compute_sweep_auth_boundary(&circuit, secret_fields, tx_body_hash);

    for position in live_positions {
        let input = &body.inputs[position];
        if expected_address[position] != input.owner.as_fields() {
            secret_fields.zeroize();
            return Err(ProveAuthorizationError::BoundaryMismatch {
                input_index: position,
                field: "owner",
            });
        }
        if expected_auth_tag[position] != input.auth_tag.as_fields() {
            secret_fields.zeroize();
            return Err(ProveAuthorizationError::BoundaryMismatch {
                input_index: position,
                field: "auth_tag",
            });
        }
    }

    let auth_inputs = SweepAuthInputs {
        spend_secret: secret_fields,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    };
    secret_fields.zeroize();
    let mut channel = sweep_auth_gkr_channel();
    let (proof, _) = prove_sweep_auth_killshot(&circuit, &auth_inputs, &mut channel);
    Ok(WalletAuthorizationBundle::Sweep25x2(proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{derive_address, hash_auth_tag, Address, AuthTag};
    use noid_tx::{hash_tx_body_for_shape, TxInput, TxOutput};

    fn mk_secret(seed: u8) -> SpendSecret {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_mul(31).wrapping_add(i as u8).wrapping_add(11);
        }
        SpendSecret(bytes)
    }

    fn standard_body_and_secret() -> (TxBody, SpendSecret) {
        let secret = mk_secret(7);
        let mut inputs = vec![TxInput {
            slot_index: 17,
            value: 100,
            owner: derive_address(&secret),
            spend_secret: SpendSecret(secret.0),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        }];
        let outputs = vec![TxOutput {
            slot_index: 29,
            value: 95,
            owner: Address([0xB0; 32]),
            valid: true,
        }];
        let tx_hash = hash_tx_body_for_shape(
            TxShape::Standard4x8,
            &[0xA5; 32],
            5,
            &inputs,
            &outputs,
            false,
        );
        inputs[0].auth_tag = hash_auth_tag(&secret, &tx_hash);
        let body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0xA5; 32],
            fee: 5,
            inputs,
            outputs,
            is_coinbase: false,
        };
        (body, secret)
    }

    fn prove_standard_fixture() -> (TxBody, SpendSecret, WalletAuthorizationBundle) {
        let (body, secret) = standard_body_and_secret();
        let bundle = prove_wallet_authorization(&body, vec![SpendSecret(secret.0)])
            .expect("prove standard authorization");
        verify_wallet_authorization(&body, &bundle).expect("verify standard authorization");
        (body, secret, bundle)
    }

    #[test]
    fn strict_decoder_rejects_trailing_bytes_and_unknown_discriminant() {
        let (_, _, bundle) = prove_standard_fixture();
        let mut bytes = bundle.to_bytes().expect("serialize authorization");
        bytes.push(0);
        assert!(matches!(
            WalletAuthorizationBundle::from_bytes(&bytes),
            Err(AuthorizationDecodeError::Bincode(_))
        ));

        let unknown_discriminant = [9u8, 0, 0, 0];
        assert!(matches!(
            WalletAuthorizationBundle::from_bytes(&unknown_discriminant),
            Err(AuthorizationDecodeError::Bincode(_))
        ));
    }

    #[test]
    fn decoder_rejects_wrong_shape_variant() {
        let (_, _, bundle) = prove_standard_fixture();
        let bytes = bundle.to_bytes().expect("serialize authorization");
        assert!(matches!(
            WalletAuthorizationBundle::from_bytes_for_shape(&bytes, TxShape::Sweep25x2),
            Err(AuthorizationDecodeError::ShapeMismatch {
                expected: TxShape::Sweep25x2,
                actual: TxShape::Standard4x8,
            })
        ));
    }

    #[test]
    fn proof_and_body_tamper_reject() {
        let (mut body, _, mut bundle) = prove_standard_fixture();

        match &mut bundle {
            WalletAuthorizationBundle::Standard4x8(proof) => {
                proof.kill_shot.main.state_at_r += Block128::ONE;
            }
            WalletAuthorizationBundle::Sweep25x2(_) => unreachable!("fixture is standard"),
        }
        assert!(matches!(
            verify_wallet_authorization(&body, &bundle),
            Err(VerifyAuthorizationError::AuthProof)
        ));

        let (_, _, honest_bundle) = prove_standard_fixture();
        body.inputs[0].owner = Address([0x44; 32]);
        assert!(matches!(
            verify_wallet_authorization(&body, &honest_bundle),
            Err(VerifyAuthorizationError::AuthProof)
        ));
    }

    #[test]
    fn missing_extra_or_wrong_secret_rejects_before_proving() {
        let (mut body, secret) = standard_body_and_secret();

        assert!(matches!(
            prove_wallet_authorization(&body, vec![]),
            Err(ProveAuthorizationError::SecretCount {
                expected: 1,
                actual: 0,
            })
        ));
        assert!(matches!(
            prove_wallet_authorization(&body, vec![SpendSecret(secret.0), mk_secret(8)]),
            Err(ProveAuthorizationError::SecretCount {
                expected: 1,
                actual: 2,
            })
        ));

        body.inputs[0].owner = Address([0x55; 32]);
        assert!(matches!(
            prove_wallet_authorization(&body, vec![SpendSecret(secret.0)]),
            Err(ProveAuthorizationError::BoundaryMismatch {
                input_index: 0,
                field: "owner",
            })
        ));
    }

    #[test]
    fn spend_secret_bytes_are_absent_from_serialization() {
        let (_, secret, bundle) = prove_standard_fixture();
        let bytes = bundle.to_bytes().expect("serialize authorization");
        assert!(
            !bytes
                .windows(secret.0.len())
                .any(|window| window == secret.0),
            "raw spend secret must not be serialized in wallet authorization"
        );
    }
}
