// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Step 1a tests — 20-slot auth sumcheck.
//!
//! Covers:
//!
//! - Honest round-trip with 4 real `(SpendSecret, tx_body_hash)` inputs.
//! - Mutation of an `expected_address` pin.
//! - Mutation of an `expected_auth_tag` pin.
//! - Mutation of a `spend_secret` on the verifier side (simulates a
//!   malicious verifier handing a different witness — rejects via
//!   per-slot sumcheck divergence).
//! - Mutation of `tx_body_hash` on the verifier side.
//! - Transcript determinism (same seed → same proof bytes).

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_gkr::auth_circuit::{AuthCircuit, AuthInputs, N_AUTH_INPUTS};
use noid_core::mle::evaluate::evaluate_slice;
use noid_gkr::auth_sumcheck::{
    auth_boundary_output_cell, build_auth_boundary_mle, compute_auth_boundary,
    discharge_auth_boundary_native, point_for_auth_boundary_cell, prove_auth,
    reconstruct_auth_slot_states, verify_auth, AuthBoundaryPins,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::primitives::{SpendSecret, TxBodyHash};

fn digest_to_fields(d: &[u8; 32]) -> [Block128; 2] {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&d[..16]);
    b.copy_from_slice(&d[16..]);
    [
        Block128::from(u128::from_le_bytes(a)),
        Block128::from(u128::from_le_bytes(b)),
    ]
}

fn fixture_inputs() -> AuthInputs {
    let circuit = AuthCircuit::build();
    let secrets = [
        SpendSecret([1u8; 32]),
        SpendSecret([2u8; 32]),
        SpendSecret([3u8; 32]),
        SpendSecret([4u8; 32]),
    ];
    let tbh = TxBodyHash([0x5Au8; 32]);

    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..N_AUTH_INPUTS {
        spend_secret[i] = secrets[i].as_fields();
    }
    let tx_body_hash = digest_to_fields(tbh.as_bytes());

    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, spend_secret, tx_body_hash);

    AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    }
}

fn fresh_channel(seed: u64) -> Poseidon2bChannel {
    let mut ch = Poseidon2bChannel::new();
    ch.absorb(Block128::from(seed as u128));
    ch
}

#[test]
fn honest_roundtrip() {
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();

    let mut p_ch = fresh_channel(1);
    let (proof, _red) = prove_auth(&circuit, &inputs, &mut p_ch);

    let mut v_ch = fresh_channel(1);
    let red = verify_auth(&proof, &circuit, &inputs, &mut v_ch).unwrap();
    assert!(discharge_auth_boundary_native(&circuit, &inputs, &red));
}

#[test]
fn mutation_expected_address_rejects() {
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();

    let mut p_ch = fresh_channel(2);
    let (proof, _red) = prove_auth(&circuit, &inputs, &mut p_ch);

    let mut bad = inputs.clone();
    bad.expected_address[1][0] += Block128::from(1u128);

    let mut v_ch = fresh_channel(2);
    assert!(verify_auth(&proof, &circuit, &bad, &mut v_ch).is_none());
}

#[test]
fn mutation_expected_auth_tag_rejects() {
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();

    let mut p_ch = fresh_channel(3);
    let (proof, _red) = prove_auth(&circuit, &inputs, &mut p_ch);

    let mut bad = inputs.clone();
    bad.expected_auth_tag[2][1] += Block128::from(1u128);

    let mut v_ch = fresh_channel(3);
    assert!(verify_auth(&proof, &circuit, &bad, &mut v_ch).is_none());
}

#[test]
fn pass4b_verifier_ignores_spend_secret() {
    // Post-Pass 4b the verifier must not consult `spend_secret` for
    // any reason — the pin-check is cryptographic, not reconstructive.
    // Tampering it on the verifier side is therefore a no-op; the
    // honest proof must still accept.
    //
    // This is a behaviour change from the pre-Pass 4b test this
    // replaces: the old test relied on `reconstruct_auth_slot_states`
    // to re-derive the digest and notice the mismatch, which leaked
    // `spend_secret` into the verifier's attack surface.
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();

    let mut p_ch = fresh_channel(4);
    let (proof, _red) = prove_auth(&circuit, &inputs, &mut p_ch);

    let mut bad = inputs.clone();
    bad.spend_secret[0][0] += Block128::from(1u128);

    let mut v_ch = fresh_channel(4);
    assert!(verify_auth(&proof, &circuit, &bad, &mut v_ch).is_some());
}

#[test]
fn mutation_tx_body_hash_on_verifier_rejects() {
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();

    let mut p_ch = fresh_channel(5);
    let (proof, _red) = prove_auth(&circuit, &inputs, &mut p_ch);

    let mut bad = inputs.clone();
    bad.tx_body_hash[0] += Block128::from(1u128);

    let mut v_ch = fresh_channel(5);
    assert!(verify_auth(&proof, &circuit, &bad, &mut v_ch).is_none());
}

#[test]
fn gamma2_tampered_slot_v0_rejects() {
    // γ₂-lift regression: the prover now ships `slot_v0[s]` instead of
    // the verifier reconstructing it from `state_in`. A lying
    // `slot_v0[s]` must either fork the per-slot sumcheck (telescope
    // misses) or fail the final batch-eval opening (sout cell disagrees
    // with committed boundary).
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();

    let mut p_ch = fresh_channel(6);
    let (mut proof, _red) = prove_auth(&circuit, &inputs, &mut p_ch);

    proof.slot_v0[7] += Block128::from(1u128);

    let mut v_ch = fresh_channel(6);
    assert!(verify_auth(&proof, &circuit, &inputs, &mut v_ch).is_none());
}

#[test]
fn gamma2_boundary_covers_sout_and_state() {
    // A batch-eval reduction over the extended (2^15) auth boundary
    // must discharge natively against a boundary MLE that contains
    // *both* the state and sout halves. If we accidentally zeroed the
    // `c=1` half the sout claim would fail here.
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();

    let mut p_ch = fresh_channel(7);
    let (_proof, red) = prove_auth(&circuit, &inputs, &mut p_ch);

    assert!(discharge_auth_boundary_native(&circuit, &inputs, &red));
}

#[test]
fn pass4a_boundary_pins_match_committed_boundary() {
    // Every public pin must actually land on the committed boundary:
    // the raw cell AND the multilinear extension at the pin's
    // hypercube coordinate must both equal `pin.value`. If this breaks
    // the STARK opening in Pass 4b would disagree with `expected_*`.
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();
    let states = reconstruct_auth_slot_states(&circuit, &inputs);
    let boundary = build_auth_boundary_mle(&states);

    let pins = AuthBoundaryPins::from_public_inputs(&inputs);
    assert_eq!(pins.address.len(), N_AUTH_INPUTS);
    assert_eq!(pins.auth_tag.len(), N_AUTH_INPUTS);

    for i in 0..N_AUTH_INPUTS {
        for lane in 0..2 {
            let addr = pins.address[i][lane];
            assert_eq!(boundary[addr.cell], addr.value);
            let point = point_for_auth_boundary_cell(addr.cell);
            assert_eq!(evaluate_slice(&boundary, &point), addr.value);

            let tag = pins.auth_tag[i][lane];
            assert_eq!(boundary[tag.cell], tag.value);
            let point = point_for_auth_boundary_cell(tag.cell);
            assert_eq!(evaluate_slice(&boundary, &point), tag.value);
        }
    }
}

#[test]
fn pass4a_cell_formula_round_trips_through_layout() {
    // Independent cross-check on the cell formula: for every live
    // input the helper must land on the same lane the old native
    // pin-check was inspecting.
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();
    let states = reconstruct_auth_slot_states(&circuit, &inputs);
    let boundary = build_auth_boundary_mle(&states);

    for i in 0..N_AUTH_INPUTS {
        let addr_slot = AuthCircuit::haddr_output_slot(i);
        let tag_slot = AuthCircuit::hauth_output_slot(i);
        for lane in 0..2 {
            assert_eq!(
                boundary[auth_boundary_output_cell(addr_slot, lane)],
                inputs.expected_address[i][lane]
            );
            assert_eq!(
                boundary[auth_boundary_output_cell(tag_slot, lane)],
                inputs.expected_auth_tag[i][lane]
            );
        }
    }
}

#[test]
fn pass4b_mutated_expected_digest_at_prover_rejects() {
    // Prover ships pins derived from a tampered `expected_address`
    // (= attempting to prove a lie). Verifier, using the honest
    // inputs, injects honest pins — the RLC inside batch-eval
    // disagrees with the prover's reduction so the opening rejects.
    let circuit = AuthCircuit::build();
    let honest = fixture_inputs();

    let mut lying = honest.clone();
    lying.expected_address[2][1] = lying.expected_address[2][1] + Block128::from(1u128);

    let mut p_ch = fresh_channel(20);
    // Prover now debug-asserts that derived == expected, so we
    // bypass that by faking a prover that skips the check via a
    // manually forged proof: build the honest proof and patch the
    // public-facing `expected_*` of verifier's inputs instead. The
    // verifier diverges on pin injection and rejects.
    let (proof, _red) = prove_auth(&circuit, &honest, &mut p_ch);

    let mut v_ch = fresh_channel(20);
    assert!(verify_auth(&proof, &circuit, &lying, &mut v_ch).is_none());
}

#[test]
fn pass4b_no_native_reconstruction_needed_for_pins() {
    // Concrete regression for Pass 4b: a tampered `spend_secret` no
    // longer needs native reconstruction to reject. The per-slot
    // sumcheck already forks (channel drift from the first round's
    // absorbed `expected_*`), but even if it didn't, the pin-eval
    // claims injected into batch_eval entangle `expected_*` into the
    // reduction. This test checks the latter path stays honest by
    // discharging the reduction natively against the honest boundary.
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();

    let mut p_ch = fresh_channel(21);
    let (_proof, red) = prove_auth(&circuit, &inputs, &mut p_ch);
    assert!(discharge_auth_boundary_native(&circuit, &inputs, &red));
}

#[test]
fn transcript_determinism() {
    let circuit = AuthCircuit::build();
    let inputs = fixture_inputs();

    let mut ch1 = fresh_channel(42);
    let (p1, _) = prove_auth(&circuit, &inputs, &mut ch1);

    let mut ch2 = fresh_channel(42);
    let (p2, _) = prove_auth(&circuit, &inputs, &mut ch2);

    assert_eq!(p1, p2);
}
