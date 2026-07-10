// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transaction proving inside the daemon.
//!
//! This is the ONLY place where the wallet's one-secret `OwnerAuthWitness` is
//! consumed by the authorization pipeline. It never leaves this function: it
//! is moved into the prover and zeroized on drop. Field-limb temporaries are
//! wallet-local proof workspace and are not serialized.
//!
//! # What this produces
//!
//! `WalletAuthorizationBundle` — the wallet's owner-batched auth proof artifact
//! submitted to the local mempool via `submitTxIntent`. The bundle is
//! forwarded from the mempool to the block prover inside the daemon.
//! AuthGKR witness tables remain wallet-local; the bundle carries one
//! self-contained owner-auth KillShot proof capsule.
//!
//! # SpendSecret handling
//!
//! The witness is taken by value and zeroized when this function returns. No
//! reference escapes. No copy is serialized or stored on disk after this
//! function completes.

use noid_gkr::{prove_wallet_authorization, OwnerAuthWitness, WalletAuthorizationBundle};
use noid_tx::TxBody;

/// Error from transaction proving.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error("wallet authorization failed: {0}")]
    Authorization(String),
}

/// Prove wallet authorization for a transaction inside the daemon.
///
/// This produces only the AuthGKR Kill-Shot authorization bundle. Public
/// transaction arithmetic is checked exactly before proving, and the canonical
/// block prover rebuilds the public AIR from `TxBody` at inclusion time.
pub fn prove_tx(
    body: &TxBody,
    witness: OwnerAuthWitness,
) -> Result<WalletAuthorizationBundle, ProveError> {
    prove_wallet_authorization(body, witness).map_err(|e| ProveError::Authorization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret};
    use noid_tx::{TxInput, TxOutput, TxShape};

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

    fn standard_body(spend_secret: &SpendSecret) -> TxBody {
        let owner = derive_address(spend_secret);
        TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0x51; 32],
            fee: 10,
            inputs: vec![TxInput {
                slot_index: 7,
                value: 1_000,
                creation_id: 17,
                owner,
                spend_secret: SpendSecret([0u8; 32]),
                valid: true,
            }],
            outputs: vec![TxOutput {
                slot_index: 70,
                value: 990,
                owner: Address([0xA7; 32]),
                valid: true,
            }],
            is_coinbase: false,
        }
    }

    fn sweep_body(spend_secret: &SpendSecret, input_count: usize) -> TxBody {
        let owner = derive_address(spend_secret);
        let mut inputs = Vec::with_capacity(input_count);
        for i in 0..input_count {
            inputs.push(TxInput {
                slot_index: 1_000 + i as u32,
                value: 10_000 + i as u64,
                creation_id: 100 + i as u64,
                owner,
                spend_secret: SpendSecret([0u8; 32]),
                valid: true,
            });
        }
        let total: u64 = inputs.iter().map(|i| i.value).sum();
        let fee = 123u64;
        TxBody {
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
        }
    }

    #[test]
    fn standard_wallet_bundle_does_not_serialize_spend_secret_bytes() {
        let spend_secret = secret(11);
        let raw_secret = spend_secret.0;
        let body = standard_body(&spend_secret);

        let bundle =
            prove_tx(&body, OwnerAuthWitness::new(spend_secret)).expect("prove standard tx");
        let bytes = bundle.to_bytes().expect("serialize wallet authorization");

        assert!(
            !contains_subslice(&bytes, &raw_secret),
            "standard wallet bundle must not contain raw spend_secret bytes"
        );
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
    fn sweep_wallet_bundle_does_not_serialize_spend_secret_bytes() {
        let spend_secret = secret(21);
        let raw_secret = spend_secret.0;
        let body = sweep_body(&spend_secret, 5);

        let bundle = prove_tx(&body, OwnerAuthWitness::new(spend_secret)).expect("prove sweep tx");
        let bytes = bundle.to_bytes().expect("serialize wallet authorization");

        assert!(
            !contains_subslice(&bytes, &raw_secret),
            "sweep wallet bundle must not contain raw spend_secret bytes"
        );
    }
}
