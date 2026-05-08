// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage D.2 — end-to-end binding between a TxBody's input leaf
//! payloads and the tx_body_merkle AIR's absorb pins.
//!
//! Symmetric to D.1 (`output_binding_end_to_end.rs`) but for the
//! input side. Each input carries four absorbed lanes:
//!   - PermA head, lane 0: `slot_index`
//!   - PermA head, lane 1: `value`
//!   - PermB non-head, lane 0: `owner_hi`
//!   - PermB non-head, lane 1: `owner_lo`
//!
//! The binding machinery is the same as for outputs: a pair of
//! `o1_payload_programme[lane]` PublicColumns pins the declared
//! payload at each leaf row-0, and head/non-head SelectorGates tie
//! either `pre_s[lane]` (PermA head) or `payload[lane]` (PermB
//! non-head) to the programme. We exhaustively tamper each end of
//! each binding chain for every input i ∈ 0..MAX_INPUTS and both
//! lanes, and assert the composite AIR rejects.
//!
//! The input side also carries an orthogonal binding — `t1_owner_tie`
//! links `TxValidityCol::OwnerHi/Lo` to `FriStateOpenAir`'s owner
//! columns per-input. That surface is covered elsewhere
//! (`t1_owner_tie.rs` unit tests) and is **not** retried here; D.2
//! focuses on the Merkle absorb-pin chain exclusively, which is what
//! authenticates the body hash against the declared input lanes.

use noid_air::airs::tx_body_merkle::air::{
    TXBODY_MERKLE_O1_BASE, TXBODY_MERKLE_O1_PROG_BASE_OFFSET, TXBODY_MERKLE_PAYLOAD_BASE,
};
use noid_air::airs::tx_body_merkle::layout::{build_instance_layout, InstanceRole};
use noid_air::airs::tx_body_merkle::TXBODY_MERKLE_PRE_S_BASE;
use noid_air::composition::tx_validity_with_spine::fixture::build_honest_realistic;
use noid_air::{Air, Trace};
use noid_core::{Block128, TowerField};
use noid_tx::MAX_INPUTS;

fn o1_prog_outer_col(merkle_offset: usize, lane: usize) -> usize {
    merkle_offset + *TXBODY_MERKLE_O1_BASE + TXBODY_MERKLE_O1_PROG_BASE_OFFSET + lane
}

fn pre_s_outer_col(merkle_offset: usize, lane: usize) -> usize {
    merkle_offset + TXBODY_MERKLE_PRE_S_BASE + lane
}

fn payload_outer_col(merkle_offset: usize, lane: usize) -> usize {
    merkle_offset + *TXBODY_MERKLE_PAYLOAD_BASE + lane
}

fn collect_input_leaf_rows() -> (Vec<usize>, Vec<usize>) {
    let layout = build_instance_layout();
    let mut perm_a = vec![usize::MAX; MAX_INPUTS];
    let mut perm_b = vec![usize::MAX; MAX_INPUTS];
    for meta in layout.iter() {
        match meta.role {
            InstanceRole::InputLeafPermA { leaf_idx } => {
                perm_a[leaf_idx as usize] = meta.slot_base_row;
            }
            InstanceRole::InputLeafPermB { leaf_idx } => {
                perm_b[leaf_idx as usize] = meta.slot_base_row;
            }
            _ => {}
        }
    }
    for i in 0..MAX_INPUTS {
        assert!(
            perm_a[i] != usize::MAX,
            "layout missing InputLeafPermA for i={i}"
        );
        assert!(
            perm_b[i] != usize::MAX,
            "layout missing InputLeafPermB for i={i}"
        );
    }
    (perm_a, perm_b)
}

#[test]
fn honest_trace_accepts() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    assert!(
        comp.air().check(&honest),
        "honest realistic fixture must verify — baseline broken",
    );
}

/// PermA head, both lanes: tamper `o1_prog[lane]` PublicColumn cell
/// at every input's PermA head row. MLE pin check must reject.
#[test]
fn tamper_input_perm_a_programme_rejects_all_i_all_lanes() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (perm_a_rows, _) = collect_input_leaf_rows();

    for i in 0..MAX_INPUTS {
        for lane in 0..2 {
            let row = perm_a_rows[i];
            let col = o1_prog_outer_col(merkle_offset, lane);
            let mut cols = honest.columns.clone();
            cols[col][row] = cols[col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "D.2(A-prog): tampering o1_prog[lane={lane}] at InputLeafPermA head row for i={i} must REJECT",
            );
        }
    }
}

/// PermA head, both lanes: tamper `pre_s[lane]` cell. Head-gated
/// SelectorGate `pre_s == o1_prog` must reject.
#[test]
fn tamper_input_perm_a_pre_s_rejects_all_i_all_lanes() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (perm_a_rows, _) = collect_input_leaf_rows();

    for i in 0..MAX_INPUTS {
        for lane in 0..2 {
            let row = perm_a_rows[i];
            let col = pre_s_outer_col(merkle_offset, lane);
            let mut cols = honest.columns.clone();
            cols[col][row] = cols[col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "D.2(A-pre_s): tampering pre_s[{lane}] at InputLeafPermA head row for i={i} must REJECT",
            );
        }
    }
}

/// PermB non-head, both lanes: tamper `o1_prog[lane]` PublicColumn
/// cell. MLE pin check must reject. Lanes 0 and 1 carry owner_hi and
/// owner_lo respectively for input i.
#[test]
fn tamper_input_perm_b_programme_rejects_all_i_all_lanes() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (_, perm_b_rows) = collect_input_leaf_rows();

    for i in 0..MAX_INPUTS {
        for lane in 0..2 {
            let row = perm_b_rows[i];
            let col = o1_prog_outer_col(merkle_offset, lane);
            let mut cols = honest.columns.clone();
            cols[col][row] = cols[col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "D.2(B-prog): tampering o1_prog[lane={lane}] at InputLeafPermB non-head row for i={i} must REJECT",
            );
        }
    }
}

/// PermB non-head, both lanes: tamper `payload[lane]` cell. The
/// non-head-gated SelectorGate `payload == o1_prog` must reject.
#[test]
fn tamper_input_perm_b_payload_rejects_all_i_all_lanes() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (_, perm_b_rows) = collect_input_leaf_rows();

    for i in 0..MAX_INPUTS {
        for lane in 0..2 {
            let row = perm_b_rows[i];
            let col = payload_outer_col(merkle_offset, lane);
            let mut cols = honest.columns.clone();
            cols[col][row] = cols[col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "D.2(B-payload): tampering payload[{lane}] at InputLeafPermB non-head row for i={i} must REJECT",
            );
        }
    }
}

/// Assertion-flip sanity: apply a PermA lane=0 tamper for i=0,
/// confirm reject, un-tamper, confirm accept. Proves the rejection
/// is caused by the flip, not by ambient state in the trace.
#[test]
fn rejection_is_attributable_to_flip() {
    let comp = build_honest_realistic();
    let honest = comp.build_trace();
    assert!(comp.air().check(&honest));

    let layout = comp.spine_layout();
    let merkle_offset = layout.merkle_block_outer_offset();
    let (perm_a_rows, _) = collect_input_leaf_rows();

    let row = perm_a_rows[0];
    let col = o1_prog_outer_col(merkle_offset, 0);
    let mut cols = honest.columns.clone();
    cols[col][row] = cols[col][row] + Block128::ONE;
    let bad = Trace::new(cols);
    assert!(!comp.air().check(&bad));

    let mut cols = bad.columns.clone();
    cols[col][row] = cols[col][row] + Block128::ONE;
    assert!(
        comp.air().check(&Trace::new(cols)),
        "un-tampering the flipped cell must restore acceptance",
    );
}
