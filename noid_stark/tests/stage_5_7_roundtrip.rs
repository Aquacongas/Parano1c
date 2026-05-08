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
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::{prove_air, verify_air};
use noid_tx::PublicInputs;

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
