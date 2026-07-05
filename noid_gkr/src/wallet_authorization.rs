// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Auth-only wallet authorization artifact.

use bincode::Options;
use noid_core::Block128;
use noid_poseidon2b::primitives::SpendSecret;
use noid_tx::{validate_public_tx_logic, PublicLogicError, TxBody, TxShape};
use serde::{Deserialize, Serialize};

use crate::{
    owner_auth_gkr_channel, owner_auth_inputs_from_body_and_live_secrets,
    owner_auth_public_from_body, prove_owner_auth_killshot, verify_owner_auth_killshot,
    OwnerAuthCircuit, OwnerAuthProofKillShot, OwnerAuthPublicInputs, OwnerAuthStatementError,
};

pub const MAX_STANDARD_AUTHORIZATION_BYTES: usize = 192 * 1024;
pub const MAX_SWEEP_AUTHORIZATION_BYTES: usize = 256 * 1024;
pub const MAX_AUTHORIZATION_BUNDLE_BYTES: usize = MAX_SWEEP_AUTHORIZATION_BYTES;

#[derive(Debug, Clone)]
pub struct CanonicalAuthorizationStatement {
    pub tx_index: usize,
    pub tx_body_hash: [Block128; 2],
    pub public: OwnerAuthPublicInputs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedAuthorization {
    pub tx_index: usize,
    pub owner_count: usize,
    pub live_input_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedAuthorizationBatch {
    pub user_tx_count: usize,
    pub owner_count_total: usize,
    pub live_input_count_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAuthorizationBundle {
    pub proof: OwnerAuthProofKillShot,
}

impl WalletAuthorizationBundle {
    pub fn to_bytes(&self) -> Result<Vec<u8>, AuthorizationEncodeError> {
        bincode_options()
            .serialize(self)
            .map_err(|e| AuthorizationEncodeError::Bincode(e.to_string()))
    }

    /// Canonical wire bytes of the bundled proof alone — the byte-exact
    /// identity used to recognize an already-verified authorization when
    /// the same proof reappears in a block sidecar.
    pub fn proof_wire_bytes(&self) -> Option<Vec<u8>> {
        authorization_proof_wire_bytes(&self.proof)
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
        Self::from_bytes(bytes)
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
    OwnerAuthStatement(String),
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
    OwnerAuthStatement(String),
    AuthProof,
}

impl From<PublicLogicError> for VerifyAuthorizationError {
    fn from(value: PublicLogicError) -> Self {
        Self::PublicLogic(value)
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
    let auth_inputs = owner_auth_inputs_from_body_and_live_secrets(body, &spend_secrets)
        .map_err(map_owner_auth_prove_error)?;
    let circuit = OwnerAuthCircuit::build(auth_inputs.layout);
    let mut channel = owner_auth_gkr_channel();
    let (proof, _) = prove_owner_auth_killshot(&circuit, &auth_inputs, &mut channel);
    Ok(WalletAuthorizationBundle { proof })
}

pub fn verify_wallet_authorization(
    body: &TxBody,
    bundle: &WalletAuthorizationBundle,
) -> Result<(), VerifyAuthorizationError> {
    verify_wallet_authorization_proof(body, &bundle.proof)
}

pub fn verify_wallet_authorization_proof(
    body: &TxBody,
    proof: &OwnerAuthProofKillShot,
) -> Result<(), VerifyAuthorizationError> {
    validate_public_tx_logic(body)?;
    let public = owner_auth_public_from_body(body)
        .map_err(|e| VerifyAuthorizationError::OwnerAuthStatement(e.to_string()))?;
    let statement = CanonicalAuthorizationStatement {
        tx_index: 0,
        tx_body_hash: public.tx_body_hash,
        public,
    };
    verify_authorization_statement_proof(&statement, proof).map(|_| ())
}

pub fn canonical_authorization_statement_from_body(
    tx_index: usize,
    tx_body_hash: [Block128; 2],
    body: &TxBody,
) -> Result<CanonicalAuthorizationStatement, OwnerAuthStatementError> {
    let public = owner_auth_public_from_body(body)?;
    Ok(CanonicalAuthorizationStatement {
        tx_index,
        tx_body_hash,
        public,
    })
}

/// Canonical wire bytes of one owner-auth proof (the encoding block
/// sidecars use). Both sides of the verified-authorization fast path —
/// mempool admission and block acceptance — compare these bytes.
pub fn authorization_proof_wire_bytes(proof: &OwnerAuthProofKillShot) -> Option<Vec<u8>> {
    bincode_options().serialize(proof).ok()
}

pub fn verify_authorization_statement_proof(
    statement: &CanonicalAuthorizationStatement,
    proof: &OwnerAuthProofKillShot,
) -> Result<VerifiedAuthorization, VerifyAuthorizationError> {
    let circuit = OwnerAuthCircuit::build(statement.public.layout);
    let mut channel = owner_auth_gkr_channel();
    verify_owner_auth_killshot(proof, &circuit, &statement.public, &mut channel)
        .ok_or(VerifyAuthorizationError::AuthProof)?;

    if statement.public.tx_body_hash != statement.tx_body_hash {
        return Err(VerifyAuthorizationError::OwnerAuthStatement(
            "statement tx_body_hash does not match canonical owner-auth public input".to_string(),
        ));
    }

    Ok(VerifiedAuthorization {
        tx_index: statement.tx_index,
        owner_count: statement.public.layout.owner_count,
        live_input_count: statement.public.live_input_positions.len(),
    })
}

fn map_owner_auth_prove_error(err: OwnerAuthStatementError) -> ProveAuthorizationError {
    match err {
        OwnerAuthStatementError::SecretCountMismatch { expected, actual } => {
            ProveAuthorizationError::SecretCount { expected, actual }
        }
        OwnerAuthStatementError::SecretMismatch { input_position } => {
            ProveAuthorizationError::BoundaryMismatch {
                input_index: input_position,
                field: "owner_auth",
            }
        }
        OwnerAuthStatementError::RepeatedOwnerSecretMismatch { input_position } => {
            ProveAuthorizationError::BoundaryMismatch {
                input_index: input_position,
                field: "repeated_owner_secret",
            }
        }
        other => ProveAuthorizationError::OwnerAuthStatement(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::{Block128, TowerField};
    use noid_poseidon2b::primitives::{derive_address, Address};
    use noid_tx::{TxInput, TxOutput};

    fn mk_secret(seed: u8) -> SpendSecret {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_mul(31).wrapping_add(i as u8).wrapping_add(11);
        }
        SpendSecret(bytes)
    }

    fn standard_body_and_secret() -> (TxBody, SpendSecret) {
        let secret = mk_secret(7);
        let inputs = vec![TxInput {
            slot_index: 17,
            value: 100,
            owner: derive_address(&secret),
            spend_secret: SpendSecret(secret.0),
            valid: true,
        }];
        let outputs = vec![TxOutput {
            slot_index: 29,
            value: 95,
            owner: Address([0xB0; 32]),
            valid: true,
        }];
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

    fn repeated_owner_body_and_secret() -> (TxBody, SpendSecret) {
        let secret = mk_secret(17);
        let inputs = vec![
            TxInput {
                slot_index: 17,
                value: 60,
                owner: derive_address(&secret),
                spend_secret: SpendSecret(secret.0),
                valid: true,
            },
            TxInput {
                slot_index: 18,
                value: 40,
                owner: derive_address(&secret),
                spend_secret: SpendSecret(secret.0),
                valid: true,
            },
        ];
        let outputs = vec![TxOutput {
            slot_index: 29,
            value: 95,
            owner: Address([0xB0; 32]),
            valid: true,
        }];
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

        let unknown_payload = [9u8, 0, 0, 0];
        assert!(matches!(
            WalletAuthorizationBundle::from_bytes(&unknown_payload),
            Err(AuthorizationDecodeError::Bincode(_))
        ));
    }

    #[test]
    fn proof_and_body_tamper_reject() {
        let (mut body, _, mut bundle) = prove_standard_fixture();

        bundle.proof.kill_shot.main.state_at_r += Block128::ONE;
        assert!(matches!(
            verify_wallet_authorization(&body, &bundle),
            Err(VerifyAuthorizationError::AuthProof)
        ));

        let (_, _, honest_bundle) = prove_standard_fixture();
        body.inputs[0].owner = Address([0x44; 32]);
        assert!(matches!(
            verify_wallet_authorization(&body, &honest_bundle),
            Err(VerifyAuthorizationError::AuthProof)
                | Err(VerifyAuthorizationError::OwnerAuthStatement(_))
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
                field: "owner_auth",
            })
        ));
    }

    #[test]
    fn repeated_owner_uses_one_owner_group() {
        let (body, secret) = repeated_owner_body_and_secret();
        let bundle =
            prove_wallet_authorization(&body, vec![SpendSecret(secret.0), SpendSecret(secret.0)])
                .expect("prove repeated-owner authorization");
        verify_wallet_authorization(&body, &bundle).expect("verify repeated-owner authorization");

        let public = owner_auth_public_from_body(&body).expect("public owner auth");
        assert_eq!(public.layout.owner_count, 1);
    }

    #[test]
    fn statement_verifier_rejects_split_tx_body_hash() {
        let (body, _, bundle) = prove_standard_fixture();
        let public = owner_auth_public_from_body(&body).expect("public owner auth");
        let mut statement =
            canonical_authorization_statement_from_body(3, public.tx_body_hash, &body)
                .expect("canonical authorization statement");
        statement.tx_body_hash[0] += Block128::ONE;

        assert!(matches!(
            verify_authorization_statement_proof(&statement, &bundle.proof),
            Err(VerifyAuthorizationError::OwnerAuthStatement(_))
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
