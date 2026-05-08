// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Regression: the tx-body Merkle AIR's wrap output must equal the
//! native `noid_tx::hash_tx_body` digest byte-for-byte on any TxBody,
//! including ones with live outputs.
//!
//! Before the TAG_OUTLEAF fix, the native `hash_output_leaf` used
//! `TAG_LEAF` + padding-flush (3 perms) while the AIR's
//! `OutputLeafPermA` seeded its capacity IV with `TAG_COMMIT` over only
//! 2 perms. The two constructions disagreed on every body that had at
//! least one `valid=true` output; no test caught it because
//! `lower_tx_body_to_pins` derives `pins.tx_body_hash` from the AIR
//! trace itself (self-consistent), never comparing to the native
//! `hash_tx_body`.
//!
//! This test closes that gap: build a TxBody, compute its digest both
//! ways, assert they match.

use noid_air::composition::tx_validity_with_spine::fixture::lower_tx_body_to_pins;
use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
use noid_tx::{hash_tx_body, TxBody, TxInput, TxOutput};

fn mk_input(seed: u8) -> TxInput {
    TxInput {
        slot_index: seed as u32,
        value: (seed as u64) * 11,
        owner: Address([seed; 32]),
        spend_secret: SpendSecret([seed ^ 0xAA; 32]),
        auth_tag: AuthTag([seed ^ 0x55; 32]),
        valid: true,
    }
}

fn mk_output(seed: u8) -> TxOutput {
    TxOutput {
        slot_index: (seed as u32).wrapping_mul(3),
        value: (seed as u64) * 7,
        owner: Address([seed; 32]),
        valid: true,
    }
}

fn native_tx_body_hash_bytes(body: &TxBody) -> [u8; 32] {
    hash_tx_body(
        &body.prev_state_root,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    )
    .into_bytes()
}

fn air_tx_body_hash_bytes(body: &TxBody) -> [u8; 32] {
    let (pins, _inputs) = lower_tx_body_to_pins(body);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&pins.tx_body_hash[0].to_u128().to_le_bytes());
    out[16..].copy_from_slice(&pins.tx_body_hash[1].to_u128().to_le_bytes());
    out
}

fn assert_air_native_parity(body: &TxBody, label: &str) {
    let native = native_tx_body_hash_bytes(body);
    let air = air_tx_body_hash_bytes(body);
    assert_eq!(
        native, air,
        "AIR tx_body_hash disagrees with native on {label}\n  native = {:02x?}\n     air = {:02x?}",
        native, air,
    );
}

#[test]
fn empty_body_matches_native() {
    let body = TxBody {
        prev_state_root: [0u8; 32],
        new_state_root: [0u8; 32],
        fee: 0,
        inputs: vec![],
        outputs: vec![],
        is_coinbase: false,
    };
    assert_air_native_parity(&body, "empty body");
}

#[test]
fn live_outputs_match_native() {
    let body = TxBody {
        prev_state_root: [0x11u8; 32],
        new_state_root: [0u8; 32],
        fee: 42,
        inputs: vec![mk_input(7), mk_input(9)],
        outputs: vec![mk_output(1), mk_output(2), mk_output(3)],
        is_coinbase: false,
    };
    assert_air_native_parity(&body, "2-in / 3-out live body");
}

#[test]
fn fully_populated_body_matches_native() {
    let body = TxBody {
        prev_state_root: [0xABu8; 32],
        new_state_root: [0u8; 32],
        fee: 123_456_789,
        inputs: (0..4).map(|i| mk_input(10 + i)).collect(),
        outputs: (0..8).map(|j| mk_output(20 + j)).collect(),
        is_coinbase: false,
    };
    assert_air_native_parity(&body, "4-in / 8-out live body");
}

#[test]
fn dummy_outputs_match_native() {
    let body = TxBody {
        prev_state_root: [0x55u8; 32],
        new_state_root: [0u8; 32],
        fee: 1,
        inputs: vec![mk_input(1)],
        outputs: vec![mk_output(2), TxOutput::dummy(), TxOutput::dummy()],
        is_coinbase: false,
    };
    assert_air_native_parity(&body, "1-in / 1-live+2-dummy-out body");
}

#[test]
fn coinbase_body_matches_native() {
    // E.5.f₂: is_coinbase=true must flow through the AIR's L14 pin
    // and produce the same digest as the native hasher.
    let body = TxBody {
        prev_state_root: [0x22u8; 32],
        new_state_root: [0u8; 32],
        fee: 0,
        inputs: vec![],
        outputs: vec![mk_output(9), mk_output(10)],
        is_coinbase: true,
    };
    assert_air_native_parity(&body, "coinbase body (is_coinbase=true)");
}

#[test]
fn coinbase_flag_flips_air_digest() {
    let body_regular = TxBody {
        prev_state_root: [0x22u8; 32],
        new_state_root: [0u8; 32],
        fee: 0,
        inputs: vec![],
        outputs: vec![mk_output(9)],
        is_coinbase: false,
    };
    let body_coinbase = TxBody {
        is_coinbase: true,
        ..body_regular.clone()
    };
    let h_r = air_tx_body_hash_bytes(&body_regular);
    let h_c = air_tx_body_hash_bytes(&body_coinbase);
    assert_ne!(h_r, h_c, "AIR digest must react to is_coinbase flip");
}
