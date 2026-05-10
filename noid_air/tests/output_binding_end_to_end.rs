// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage D.1 baseline — the honest realistic fixture still accepts.
//!
//! Historically this file exhaustively tampered the Merkle-side absorb
//! pin chain (`o1_prog[lane]`, `pre_s[lane]`, `payload[lane]`) at
//! every `OutputLeafPermA` / `OutputLeafPermB` row and asserted each
//! tamper rejected. Those cells are gone — the 59-perm Merkle band is
//! retired and GKR owns the permutation soundness. Output-lane
//! binding is now closed by the row-wide `tx_body_hash` pin on
//! `TXBODY_MERKLE_LAYOUT.s` / `.s + 1`; cross-row leaf coverage lives
//! in the GKR spine-sumcheck mutation tests.

use noid_air::composition::tx_validity_with_spine::fixture::build_honest_realistic;
use noid_air::Air;

#[test]
fn honest_trace_accepts() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    assert!(
        comp.air().check(&honest),
        "honest realistic fixture must verify — baseline broken",
    );
}
