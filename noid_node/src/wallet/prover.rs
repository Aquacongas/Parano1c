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
//! Secret-bearing Poseidon state remains wallet-local; the bundle carries one
//! self-contained witness-hiding selected authorization capsule.
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
/// This produces only the selected witness-hiding authorization bundle. Public
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
    use noid_tx::{output_bitmap_bit, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

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

    fn body(spend_secret: &SpendSecret, input_count: usize) -> TxBody {
        let owner = derive_address(spend_secret);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        let mut total = 0u64;
        for i in 0..input_count {
            inputs[i] = TxInput {
                slot_index: 1_000 + i as u32,
                amount: 10_000 + i as u64,
                creation_id: 100 + i as u64,
            };
            total += inputs[i].amount;
        }
        let fee = 123u64;
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 50_000,
            amount: total - fee,
            owner: Address([0xB1; 32]),
        };
        TxBody {
            epoch_anchor: [0x52; 32],
            fee,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: ((1u16 << input_count) - 1) | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    #[test]
    fn wallet_bundle_does_not_serialize_spend_secret_bytes() {
        let spend_secret = secret(11);
        let raw_secret = spend_secret.0;
        let body = body(&spend_secret, 1);

        let bundle =
            prove_tx(&body, OwnerAuthWitness::new(spend_secret)).expect("prove transaction");
        let bytes = bundle.to_bytes().expect("serialize wallet authorization");

        assert!(
            !contains_subslice(&bytes, &raw_secret),
            "wallet bundle must not contain raw spend_secret bytes"
        );
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only eight-input proof regression")]
    fn eight_input_wallet_bundle_does_not_serialize_spend_secret_bytes() {
        let spend_secret = secret(21);
        let raw_secret = spend_secret.0;
        let body = body(&spend_secret, TX_INPUTS);

        let bundle = prove_tx(&body, OwnerAuthWitness::new(spend_secret))
            .expect("prove eight-input transaction");
        let bytes = bundle.to_bytes().expect("serialize wallet authorization");

        assert!(
            !contains_subslice(&bytes, &raw_secret),
            "eight-input wallet bundle must not contain raw spend_secret bytes"
        );
    }
}
