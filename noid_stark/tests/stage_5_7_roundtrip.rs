// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.
//
// Stage 5.7 acceptance (c) + Stage 6 PI binding.
//
// `stage_5_7_prove_verify_roundtrip` — empty-TxBody honest fixture,
// placeholder PI (preserved for continuity).
//
// `stage_6_prove_verify_roundtrip_realistic_pi` — non-empty TxBody
// fixture with a real `PublicInputs` derived from the composite's
// sub-AIR pins via `public_inputs()`. The verifier absorbs PI into
// Fiat-Shamir and the `check_public_columns` MLE re-eval binds each
// pin; tampering any of the four PI scalars at verify time makes
// `verify_air` reject.

use noid_air::{
    composition::{build_stage_5_7_honest_fixture, tx_validity_with_spine::fixture},
    Air,
};
use noid_core::{Block128, TowerField};
use noid_gkr::{
    compute_auth_boundary, AuthCircuit, AuthInputs, SpineInputs, N_AUTH_INPUTS,
};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::auth::{prove_air_with_auth, verify_air_with_auth};
use noid_stark::spine::{prove_air_with_spine, verify_air_with_spine};
use noid_stark::{prove_air, verify_air};
use noid_tx::PublicInputs;

/// Lower the composite's boundary pins to the `SpineInputs` shape the
/// GKR spine consumes. Mirrors the pin semantics documented on
/// `TxBodyMerkleBoundaryPins`: the tree-leaf ordering is
/// `[L0, L1, L2..L5, L6..L13, L14, L15]`.
fn spine_inputs_from_composite(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> SpineInputs {
    let pins = comp.boundary_pins();
    SpineInputs {
        prev_state_root: pins.prev_state_root,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    }
}

/// Build an honest `AuthInputs` anchored to the composite's tx-body
/// hash. The auth boundary is orthogonal to the STARK's own input-owner
/// pins — this test picks four arbitrary non-zero secrets and pins the
/// claimed `(address, auth_tag)` pair to the circuit's native output.
fn honest_auth_inputs(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> AuthInputs {
    let circuit = AuthCircuit::build();
    let spend_secret: [[Block128; 2]; N_AUTH_INPUTS] = [
        [Block128::from(0xA1u128), Block128::from(0xA2u128)],
        [Block128::from(0xB1u128), Block128::from(0xB2u128)],
        [Block128::from(0xC1u128), Block128::from(0xC2u128)],
        [Block128::from(0xD1u128), Block128::from(0xD2u128)],
    ];
    let tx_body_hash = comp.tx_body_hash_fields();
    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, spend_secret, tx_body_hash);
    AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    }
}

#[test]
#[ignore = "stage_5_7_roundtrip: heavy (2^13 rows × ~2100 cols); run with --ignored"]
fn stage_5_7_prove_verify_roundtrip() {
    let comp = build_stage_5_7_honest_fixture();
    let trace = comp.build_trace();
    assert!(comp.air().check(&trace), "honest trace accepted by Air::check");

    // Empty-TxBody fixture pins `prev_state_root` / `new_state_root`
    // to the honest combiner preimage digests and `tx_body_hash` to
    // the Merkle wrap-output; derive PI from the composite itself.
    let pi = comp.public_inputs();
    comp.assert_public_inputs_consistent(&pi);

    let proof = prove_air(comp.air(), &trace, &pi).expect("prove");
    verify_air(comp.air(), &pi, &proof).expect("verify");
}

/// Stage 6 acceptance (c) — single PI surface round-trip on the
/// realistic non-empty TxBody fixture (2 live inputs, 4 live outputs,
/// fee 50, balance 150 = 100 + 50).
#[test]
#[ignore = "stage_6_roundtrip: heavy; run with --ignored"]
fn stage_6_prove_verify_roundtrip_realistic_pi() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    assert!(comp.air().check(&trace));

    let pi = comp.public_inputs();
    comp.assert_public_inputs_consistent(&pi);

    let proof = prove_air(comp.air(), &trace, &pi).expect("prove");
    verify_air(comp.air(), &pi, &proof).expect("verify");
}

/// Stage 6 acceptance (a) — tampering `prev_state_root` in the PI
/// passed to `verify_air` must cause rejection. The verifier absorbs
/// PI into the Fiat-Shamir channel, so any mutation desyncs the
/// replayed transcript from the prover's and at least one downstream
/// check fails.
#[test]
#[ignore = "stage_6_pi_tamper: heavy; run with --ignored"]
fn stage_6_verify_rejects_tampered_prev_state_root() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let honest_pi = comp.public_inputs();
    let proof = prove_air(comp.air(), &trace, &honest_pi).expect("prove");

    let mut bad = honest_pi;
    bad.prev_state_root[0] ^= 0xFF;
    assert!(
        verify_air(comp.air(), &bad, &proof).is_err(),
        "verify_air must reject tampered prev_state_root",
    );
}

#[test]
#[ignore = "stage_6_pi_tamper: heavy; run with --ignored"]
fn stage_6_verify_rejects_tampered_new_state_root() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let honest_pi = comp.public_inputs();
    let proof = prove_air(comp.air(), &trace, &honest_pi).expect("prove");

    let mut bad = honest_pi;
    bad.new_state_root[0] ^= 0xFF;
    assert!(
        verify_air(comp.air(), &bad, &proof).is_err(),
        "verify_air must reject tampered new_state_root",
    );
}

#[test]
#[ignore = "stage_6_pi_tamper: heavy; run with --ignored"]
fn stage_6_verify_rejects_tampered_tx_body_hash() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let honest_pi = comp.public_inputs();
    let proof = prove_air(comp.air(), &trace, &honest_pi).expect("prove");

    let mut bad_bytes = honest_pi.tx_body_hash.0;
    bad_bytes[0] ^= 0xFF;
    let bad = PublicInputs {
        tx_body_hash: TxBodyHash(bad_bytes),
        ..honest_pi
    };
    assert!(
        verify_air(comp.air(), &bad, &proof).is_err(),
        "verify_air must reject tampered tx_body_hash",
    );
}

#[test]
#[ignore = "stage_6_pi_tamper: heavy; run with --ignored"]
fn stage_6_verify_rejects_tampered_fee() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let honest_pi = comp.public_inputs();
    let proof = prove_air(comp.air(), &trace, &honest_pi).expect("prove");

    let mut bad = honest_pi;
    bad.fee = bad.fee.wrapping_add(1);
    assert!(
        verify_air(comp.air(), &bad, &proof).is_err(),
        "verify_air must reject tampered fee",
    );
}

/// Stage 6 acceptance (c) — the consistency assert fires if the
/// caller hands `new` / `with_public_inputs` a mismatching PI. Light
/// enough to run in the default test set.
#[test]
#[should_panic(expected = "PublicInputs.fee disagrees with balance-block pin")]
fn stage_6_consistency_assert_detects_pi_fee_mismatch() {
    let comp = fixture::build_honest_realistic();
    let mut pi = comp.public_inputs();
    pi.fee = pi.fee.wrapping_add(1);
    comp.assert_public_inputs_consistent(&pi);
}

#[test]
#[should_panic(expected = "PublicInputs.prev_state_root disagrees")]
fn stage_6_consistency_assert_detects_pi_prev_state_root_mismatch() {
    let comp = fixture::build_honest_realistic();
    let mut pi = comp.public_inputs();
    pi.prev_state_root[0] ^= 0xFF;
    comp.assert_public_inputs_consistent(&pi);
}

/// Stage E.6 — `log_slots` is absorbed into the Fiat-Shamir channel
/// alongside the roots, so swapping it on the verifier side must
/// desync the replayed transcript and make `verify_air` fail.
#[test]
#[ignore = "stage_e6_pi_tamper: heavy; run with --ignored"]
fn stage_e6_verify_rejects_tampered_log_slots() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let honest_pi = comp.public_inputs();
    let proof = prove_air(comp.air(), &trace, &honest_pi).expect("prove");

    let mut bad = honest_pi;
    bad.log_slots = bad.log_slots.wrapping_add(1);
    assert!(
        verify_air(comp.air(), &bad, &proof).is_err(),
        "verify_air must reject tampered log_slots",
    );
}

/// Stage E.6 — caller-supplied PI must match the combiner preimage's
/// `log_slots`; the consistency assert surfaces a mismatch at
/// composite construction time.
#[test]
#[should_panic(expected = "PublicInputs.log_slots disagrees")]
fn stage_e6_consistency_assert_detects_pi_log_slots_mismatch() {
    let comp = fixture::build_honest_realistic();
    let mut pi = comp.public_inputs();
    pi.log_slots = pi.log_slots.wrapping_add(1);
    comp.assert_public_inputs_consistent(&pi);
}

// ---------------------------------------------------------------------------
// Phase 1 Step 1 — Skinny STARK / Fat GKR round-trips.
//
// The 59-perm tx-body spine and the per-input Address/AuthTag sponges
// have been evacuated from the STARK. Verification now staples two
// independent Fiat-Shamir runs (STARK + SpineGKR, STARK + AuthGKR)
// through one shared FRI boundary commitment and one shared
// `(r_B, v_B)` reduction per sub-protocol.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "phase1_step1_spine_roundtrip: heavy; run with --ignored"]
fn phase1_step1_prove_verify_with_spine_roundtrip() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    assert!(comp.air().check(&trace));

    let pi = comp.public_inputs();
    comp.assert_public_inputs_consistent(&pi);

    let spine_inputs = spine_inputs_from_composite(&comp);
    let proof = prove_air_with_spine(comp.air(), &trace, &pi, &spine_inputs).expect("prove");
    verify_air_with_spine(comp.air(), &pi, &spine_inputs, &proof).expect("verify");
}

#[test]
#[ignore = "phase1_step1_auth_roundtrip: heavy; run with --ignored"]
fn phase1_step1_prove_verify_with_auth_roundtrip() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    assert!(comp.air().check(&trace));

    let pi = comp.public_inputs();
    comp.assert_public_inputs_consistent(&pi);

    let auth_inputs = honest_auth_inputs(&comp);
    let proof = prove_air_with_auth(comp.air(), &trace, &pi, &auth_inputs).expect("prove");
    verify_air_with_auth(comp.air(), &pi, &auth_inputs, &proof).expect("verify");
}
