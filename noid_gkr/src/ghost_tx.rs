// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The canonical GHOST transaction — the protocol constant that pads a
//! block's user-transaction list to its shape-tier capacity.
//!
//! Two same-tier blocks with different REAL transaction counts must
//! assemble to one fixed proof class (the fixed-matrix invariant), so
//! every per-transaction slot past the real count is filled with THIS
//! transaction: its spine chain joins the tx-body killshot batch, its
//! authorization proof joins the region walks, and its statement lanes
//! are the constants below. Ghost slots are marked dead by liveness
//! selectors — they never touch state, never enter the tx root, and
//! contribute zero to every resource total.
//!
//! SECURITY: the ghost spend secret is DELIBERATELY PUBLIC — it is a
//! protocol constant, not a wallet secret. It authorizes only the ghost
//! body defined here, which spends a slot that never exists in any
//! chain state (liveness gating keeps ghost slots out of all state
//! semantics), so knowing the "secret" grants nothing. Real wallet
//! secrets never leave wallets; this constant is not one of them.

use std::sync::OnceLock;

use noid_core::Block128;
use noid_poseidon2b::primitives::{derive_address, SpendSecret};
use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

use crate::owner_auth::{owner_auth_public_from_body, OwnerAuthPublicInputs};
use crate::wallet_authorization::{
    prove_wallet_authorization, verify_wallet_authorization_proof, OwnerAuthWitness,
};
use crate::OwnerAuthProofKillShot;

/// The public protocol "secret" of the ghost owner (ASCII domain tag,
/// exactly 32 bytes). See the module doc for why this is public by design.
pub fn ghost_spend_secret() -> SpendSecret {
    SpendSecret(*b"PARANOID-GHOST-TX-SPEND-SECRET.0")
}

/// The canonical ghost body: fixed Tx8x2, zero epoch anchor, zero
/// fee, ONE live input of value 1 owned by the ghost address, ONE live
/// output of value 1 back to the ghost address (balance holds), all other
/// slots dummy. Passes `validate_public_tx_logic` by construction.
pub fn ghost_tx_body() -> TxBody {
    let secret = ghost_spend_secret();
    let owner = derive_address(&secret);
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    inputs[0] = TxInput {
        slot_index: 0,
        amount: 1,
        creation_id: 0,
    };
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    outputs[0] = TxOutput {
        // Distinct from the ghost input so the canonical public-logic
        // no-overlap rule holds even before block-level ghost gating.
        slot_index: 1,
        amount: 1,
        owner,
    };
    TxBody {
        epoch_anchor: [0u8; 32],
        fee: 0,
        input_owner: owner,
        inputs,
        outputs,
        validity_bitmap: 1 | output_bitmap_bit(0),
        is_coinbase: false,
    }
}

/// The ghost body hash lanes — the constant ghost spine chains hash to and
/// ghost authorization statements bind.
pub fn ghost_tx_body_hash() -> [Block128; 2] {
    ghost_authorization().1.tx_body_hash
}

/// The ghost authorization unit: the owner-auth killshot proof (capsule
/// included) plus its canonical public statement, proven ONCE per process
/// from the constants above and reused for every ghost slot of every
/// block. Deterministic: the proof transcript is Fiat–Shamir over fixed
/// inputs, so every node derives byte-identical ghost data.
pub fn ghost_authorization() -> &'static (OwnerAuthProofKillShot, OwnerAuthPublicInputs) {
    static GHOST: OnceLock<(OwnerAuthProofKillShot, OwnerAuthPublicInputs)> = OnceLock::new();
    GHOST.get_or_init(|| {
        let body = ghost_tx_body();
        let bundle = prove_wallet_authorization(&body, OwnerAuthWitness::new(ghost_spend_secret()))
            .expect("the canonical ghost body must be provable");
        verify_wallet_authorization_proof(&body, &bundle.proof)
            .expect("the canonical ghost proof must verify");
        let public =
            owner_auth_public_from_body(&body).expect("the canonical ghost statement derives");
        (bundle.proof, public)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_tx::validate_public_tx_logic;

    /// GOLDEN: the ghost body's committed validity bitmap is 257 (one live
    /// input at bit 0 + one live output at bit 8) — NOT zero.
    /// The bitmap leaf therefore changed the ghost body hash when it
    /// landed; every ghost constant DERIVES from the body, so consumers
    /// stay consistent by construction, and this test pins the derivation
    /// so a silent bitmap-rule drift cannot change the ghost identity
    /// unnoticed.
    #[test]
    fn ghost_body_bitmap_is_257_and_hash_derives_from_it() {
        let body = ghost_tx_body();
        assert_eq!(body.validity_bitmap, 257, "input 0 + output 0");
        let recomputed = body.txid();
        assert_eq!(
            [recomputed.as_fields()[0], recomputed.as_fields()[1]],
            ghost_tx_body_hash(),
            "ghost body hash != canonical re-derivation"
        );
    }

    #[test]
    fn ghost_body_passes_public_logic_and_proof_verifies() {
        let body = ghost_tx_body();
        let facts = validate_public_tx_logic(&body).expect("ghost body public logic");
        assert_eq!(facts.fee_u64, 0);
        assert_eq!(facts.n_live_inputs, 1);
        assert_eq!(facts.n_live_outputs, 1);
        assert_eq!(facts.input_sum, 1);
        assert_eq!(facts.output_sum, 1);

        let (proof, public) = ghost_authorization();
        assert_eq!(public.tx_body_hash, ghost_tx_body_hash());
        verify_wallet_authorization_proof(&ghost_tx_body(), proof)
            .expect("ghost authorization verifies");
    }

    #[test]
    fn ghost_authorization_is_deterministic() {
        // Two independent proves over the constant body produce identical
        // proofs (Fiat–Shamir over fixed inputs — no prover randomness).
        let body = ghost_tx_body();
        let a =
            prove_wallet_authorization(&body, OwnerAuthWitness::new(ghost_spend_secret())).unwrap();
        let b =
            prove_wallet_authorization(&body, OwnerAuthWitness::new(ghost_spend_secret())).unwrap();
        assert_eq!(
            crate::wallet_authorization::authorization_proof_wire_bytes(&a.proof),
            crate::wallet_authorization::authorization_proof_wire_bytes(&b.proof),
            "ghost proof must be deterministic"
        );
    }
}
