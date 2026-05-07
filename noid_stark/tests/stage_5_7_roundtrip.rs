// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.
//
// Stage 5.7 acceptance (c): `prove_air` + `verify_air` round-trip on the
// unified `TxValidityCompositeWithSpine`. Exercises the full
// leaf-band + embedded spine composite under FRI/sumcheck. No Stage 6
// `PublicInputs`-to-trace binding yet — the PI struct is passed
// through but not checked by the verifier (that lands in Stage 6).

use noid_air::{composition::build_stage_5_7_honest_fixture, Air};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::{prove_air, verify_air};
use noid_tx::PublicInputs;

#[test]
#[ignore = "stage_5_7_roundtrip: heavy (2^13 rows × ~2100 cols); run with --ignored"]
fn stage_5_7_prove_verify_roundtrip() {
    let comp = build_stage_5_7_honest_fixture();
    let trace = comp.build_trace();
    assert!(comp.air().check(&trace), "honest trace accepted by Air::check");

    // Stage 5.7 PI surface is not binding yet — Stage 6 pins the four
    // scalars. Provide a placeholder PI; the verifier will accept.
    let pi = PublicInputs {
        prev_state_root: [0u8; 32],
        new_state_root: [0u8; 32],
        tx_body_hash: TxBodyHash([0u8; 32]),
        fee: 0,
    };

    let proof = prove_air(comp.air(), &trace, &pi).expect("prove");
    verify_air(comp.air(), &pi, &proof).expect("verify");
}
