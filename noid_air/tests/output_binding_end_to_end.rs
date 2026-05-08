// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage D.1 — end-to-end binding between a TxBody's output leaf
//! payloads and the tx_body_merkle AIR's absorb pins.
//!
//! After Stage B the sole committed output path is through
//! `TxBodyMerkleAir`'s `o1_payload_programme[lane]` PublicColumn and
//! the head-gated `SelectorGate(pre_s[lane] == o1_prog[lane])`. This
//! test parameterizes over all output indices `j ∈ 0..MAX_OUTPUTS`,
//! both PermA lanes (`value`, `owner_hi`) and the PermB lane
//! (`owner_lo`), tampering **each** end of each binding chain and
//! asserting the composite AIR rejects. It is the exhaustive version
//! of Stage B.4's `tamper_output_leaf_absorb_pin_rejects`, covering
//! the full layout rather than the single output j=0 / two lanes
//! demonstrated there.
//!
//! Coverage (per output j) — Stage E.1 4-lane schema
//! (`hash_output_leaf([slot_index, value, owner_hi, owner_lo])`):
//!   - PermA head row × lane 0: `pins.output_leaf_absorb[j][0]` = slot_index.
//!   - PermA head row × lane 1: `pins.output_leaf_absorb[j][1]` = value.
//!   - PermB non-head row × lane 0: `pins.output_leaf_absorb[j][2]` = owner_hi.
//!   - PermB non-head row × lane 1: `pins.output_leaf_absorb[j][3]` = owner_lo.
//!
//! For each (j, lane, role), the test flips one `Block128::ONE` into:
//!   (a) the `o1_payload_programme[lane]` PublicColumn cell at that row,
//!       which must fail the public-column MLE pin check, and
//!   (b) the `pre_s[lane]` (PermA head) or `payload[lane]` (PermB
//!       non-head) cell at that row, which must fail the
//!       head/non-head SelectorGate constraint.
//!
//! If any single flip is accepted, the output binding is not tight
//! and a forger can substitute an output leaf payload without the
//! Merkle hash reflecting the change. Regression-guard for §I.1
//! predicate 8 (`tx_body_hash` commitment).

use noid_air::airs::tx_body_merkle::air::{
    TXBODY_MERKLE_O1_BASE, TXBODY_MERKLE_O1_PROG_BASE_OFFSET, TXBODY_MERKLE_PAYLOAD_BASE,
};
use noid_air::airs::tx_body_merkle::layout::{build_instance_layout, InstanceRole};
use noid_air::airs::tx_body_merkle::TXBODY_MERKLE_PRE_S_BASE;
use noid_air::composition::tx_validity_with_spine::fixture::build_honest_realistic;
use noid_air::{Air, Trace};
use noid_core::{Block128, TowerField};
use noid_tx::MAX_OUTPUTS;

/// Outer column carrying the `o1_payload_programme[lane]`
/// PublicColumn inside the embedded Merkle block.
fn o1_prog_outer_col(merkle_offset: usize, lane: usize) -> usize {
    merkle_offset + *TXBODY_MERKLE_O1_BASE + TXBODY_MERKLE_O1_PROG_BASE_OFFSET + lane
}

/// Outer column carrying `pre_s[lane]` inside the embedded Merkle
/// block. Used for PermA-head tampering (lane ∈ {0,1}) — pinned to
/// `o1_prog[lane]` by the head-gated SelectorGate.
fn pre_s_outer_col(merkle_offset: usize, lane: usize) -> usize {
    merkle_offset + TXBODY_MERKLE_PRE_S_BASE + lane
}

/// Outer column carrying `payload[lane]` inside the embedded Merkle
/// block. Stage E.1: both PermB lanes on the output side are now
/// body-derived (lane 0 = owner_hi, lane 1 = owner_lo) — symmetric
/// with the input side.
fn payload_outer_col(merkle_offset: usize, lane: usize) -> usize {
    merkle_offset + *TXBODY_MERKLE_PAYLOAD_BASE + lane
}

/// Gather the slot_base_row for every output PermA / PermB instance.
/// Output j appears exactly once in each role by layout invariant.
fn collect_output_leaf_rows() -> (Vec<usize>, Vec<usize>) {
    let layout = build_instance_layout();
    let mut perm_a = vec![usize::MAX; MAX_OUTPUTS];
    let mut perm_b = vec![usize::MAX; MAX_OUTPUTS];
    for meta in layout.iter() {
        match meta.role {
            InstanceRole::OutputLeafPermA { leaf_idx } => {
                perm_a[leaf_idx as usize] = meta.slot_base_row;
            }
            InstanceRole::OutputLeafPermB { leaf_idx } => {
                perm_b[leaf_idx as usize] = meta.slot_base_row;
            }
            _ => {}
        }
    }
    for j in 0..MAX_OUTPUTS {
        assert!(
            perm_a[j] != usize::MAX,
            "layout missing OutputLeafPermA for j={j}"
        );
        assert!(
            perm_b[j] != usize::MAX,
            "layout missing OutputLeafPermB for j={j}"
        );
    }
    (perm_a, perm_b)
}

/// Preserve the honest trace baseline: an untampered trace must
/// accept. If this invariant breaks the whole file is meaningless.
#[test]
fn honest_trace_accepts() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    assert!(
        comp.air().check(&honest),
        "honest realistic fixture must verify — baseline broken"
    );
}

/// For every output j and every lane ∈ {0,1}, tamper the
/// `o1_payload_programme[lane]` PublicColumn cell at the PermA head
/// row. MLE pin check must reject.
#[test]
fn tamper_output_perm_a_programme_rejects_all_j_all_lanes() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (perm_a_rows, _) = collect_output_leaf_rows();

    for j in 0..MAX_OUTPUTS {
        for lane in 0..2 {
            let row = perm_a_rows[j];
            let col = o1_prog_outer_col(merkle_offset, lane);
            let mut cols = honest.columns.clone();
            cols[col][row] = cols[col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "D.1(A-prog): tampering o1_prog[lane={lane}] at OutputLeafPermA head row for j={j} must REJECT",
            );
        }
    }
}

/// For every output j and every lane ∈ {0,1}, tamper the `pre_s[lane]`
/// cell at the PermA head row. The head-gated SelectorGate
/// `pre_s == o1_prog` must reject.
#[test]
fn tamper_output_perm_a_pre_s_rejects_all_j_all_lanes() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (perm_a_rows, _) = collect_output_leaf_rows();

    for j in 0..MAX_OUTPUTS {
        for lane in 0..2 {
            let row = perm_a_rows[j];
            let col = pre_s_outer_col(merkle_offset, lane);
            let mut cols = honest.columns.clone();
            cols[col][row] = cols[col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "D.1(A-pre_s): tampering pre_s[{lane}] at OutputLeafPermA head row for j={j} must REJECT",
            );
        }
    }
}

/// For every output j and every lane ∈ {0,1}, tamper
/// `o1_payload_programme[lane]` at the PermB non-head row — this
/// carries `pins.output_leaf_absorb[j][2 + lane]` (owner_hi / owner_lo).
#[test]
fn tamper_output_perm_b_programme_rejects_all_j_all_lanes() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (_, perm_b_rows) = collect_output_leaf_rows();

    for j in 0..MAX_OUTPUTS {
        for lane in 0..2 {
            let row = perm_b_rows[j];
            let col = o1_prog_outer_col(merkle_offset, lane);
            let mut cols = honest.columns.clone();
            cols[col][row] = cols[col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "D.1(B-prog): tampering o1_prog[lane={lane}] at OutputLeafPermB non-head row for j={j} must REJECT",
            );
        }
    }
}

/// For every output j and every lane ∈ {0,1}, tamper `payload[lane]`
/// at the PermB non-head row. Stage E.1: both lanes are body-derived
/// (owner_hi, owner_lo) — symmetric with the input side. Non-head
/// SelectorGate `payload == o1_prog` must reject.
#[test]
fn tamper_output_perm_b_payload_rejects_all_j_all_lanes() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (_, perm_b_rows) = collect_output_leaf_rows();

    for j in 0..MAX_OUTPUTS {
        for lane in 0..2 {
            let row = perm_b_rows[j];
            let col = payload_outer_col(merkle_offset, lane);
            let mut cols = honest.columns.clone();
            cols[col][row] = cols[col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "D.1(B-payload): tampering payload[{lane}] at OutputLeafPermB non-head row for j={j} must REJECT",
            );
        }
    }
}

/// Control: flipping an arbitrary cell in an honest trace at a row
/// with no absorb-pin binding (a deep interior permutation row) does
/// not automatically reject via the same mechanism — it rejects via
/// a *different* constraint. Assertion-flip sanity check: each tamper
/// above must genuinely reject, not vacuously pass because the tamper
/// landed on a dead cell.
///
/// Concretely: we re-run the PermA head tamper for j=0, lane=0, and
/// confirm the honest check at that exact cell accepts (so the
/// rejection is attributable to the flip).
#[test]
fn rejection_is_attributable_to_flip() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    assert!(comp.air().check(&honest));

    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (perm_a_rows, _) = collect_output_leaf_rows();

    let row = perm_a_rows[0];
    let col = o1_prog_outer_col(merkle_offset, 0);
    let mut cols = honest.columns.clone();
    cols[col][row] = cols[col][row] + Block128::ONE;
    let bad = Trace::new(cols);
    assert!(!comp.air().check(&bad));

    // Un-tamper → accept again, proving the rejection was caused by
    // this single flip, not some pre-existing state.
    let mut cols = bad.columns.clone();
    cols[col][row] = cols[col][row] + Block128::ONE;
    assert!(
        comp.air().check(&Trace::new(cols)),
        "un-tampering the flipped cell must restore acceptance",
    );
}
