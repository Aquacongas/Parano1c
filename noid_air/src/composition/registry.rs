// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Typed column registries for Stage 5 composite wiring.
//!
//! Every registry is a plain-data struct of column indices. It is
//! built from the existing `pub const` offsets of its source AIR and
//! carries no state. Bridge destinations and row-window wrappers
//! address cells through these registries instead of raw `usize`
//! offsets.
//!
//! Row conventions matter as much as column conventions. Where a
//! sub-AIR holds a per-instance payload at row `i` (e.g. AuthTag at
//! row `i` in `TxValidityAir`, or `(value, owner_hi, owner_lo)` at
//! row `i` in `FriStateOpenAir`), the registry exposes it as a
//! `(col, row)` accessor so the Stage 5 caller cannot pick a wrong
//! row by accident.

use crate::airs::{
    fri_state_combiner::COMBINER_PERM_LAYOUT,
    fri_state_combiner_composite::{COMBINER_COMPOSITE_NEW_OFFSET, COMBINER_COMPOSITE_PREV_OFFSET},
    fri_state_open::{COL_OWNER_HI, COL_OWNER_LO, COL_VALUE, FRI_STATE_OPEN_N_INPUTS},
    tx_body_merkle::{build_instance_layout, leaf_rate_payload_col, InstanceRole},
    tx_validity::TxValidityCol,
};
use noid_tx::types::{MAX_INPUTS, MAX_OUTPUTS};

/// Column + row of a single cell in a sub-AIR trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub col: usize,
    pub row: usize,
}

impl Cell {
    #[inline]
    pub const fn new(col: usize, row: usize) -> Self {
        Self { col, row }
    }
}

/// `TxValidityAir` (3a / 3b-4) — per-input AuthTag destinations for
/// Stage 5 T2a. Input `i` lives on row `i` of the witness region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxValidityCols {
    pub auth_tag_hi: [Cell; MAX_INPUTS],
    pub auth_tag_lo: [Cell; MAX_INPUTS],
    pub value: [Cell; MAX_INPUTS + MAX_OUTPUTS],
    pub owner_hi: [Cell; MAX_INPUTS + MAX_OUTPUTS],
    pub owner_lo: [Cell; MAX_INPUTS + MAX_OUTPUTS],
    pub slot_index: [Cell; MAX_INPUTS],
}

impl TxValidityCols {
    pub const fn new() -> Self {
        let hi = TxValidityCol::AuthTagHi.index();
        let lo = TxValidityCol::AuthTagLo.index();
        let val = TxValidityCol::Value.index();
        let oh = TxValidityCol::OwnerHi.index();
        let ol = TxValidityCol::OwnerLo.index();
        let slot = TxValidityCol::SlotIndex.index();

        let mut auth_tag_hi = [Cell::new(0, 0); MAX_INPUTS];
        let mut auth_tag_lo = [Cell::new(0, 0); MAX_INPUTS];
        let mut slot_index = [Cell::new(0, 0); MAX_INPUTS];
        let mut i = 0;
        while i < MAX_INPUTS {
            auth_tag_hi[i] = Cell::new(hi, i);
            auth_tag_lo[i] = Cell::new(lo, i);
            slot_index[i] = Cell::new(slot, i);
            i += 1;
        }

        let total = MAX_INPUTS + MAX_OUTPUTS;
        let mut value = [Cell::new(0, 0); MAX_INPUTS + MAX_OUTPUTS];
        let mut owner_hi = [Cell::new(0, 0); MAX_INPUTS + MAX_OUTPUTS];
        let mut owner_lo = [Cell::new(0, 0); MAX_INPUTS + MAX_OUTPUTS];
        let mut k = 0;
        while k < total {
            value[k] = Cell::new(val, k);
            owner_hi[k] = Cell::new(oh, k);
            owner_lo[k] = Cell::new(ol, k);
            k += 1;
        }

        Self {
            auth_tag_hi,
            auth_tag_lo,
            value,
            owner_hi,
            owner_lo,
            slot_index,
        }
    }
}

impl Default for TxValidityCols {
    fn default() -> Self {
        Self::new()
    }
}

/// `TxBodyMerkleAir` — leaf-rate payload lanes and per-output rows.
///
/// Layout note: under E.4.c-1 collapse, `leaf_rate_payload_col(slot, lane)`
/// does **not** depend on `slot` — all 16 leaf payloads share a single
/// column per lane and are distinguished by *row*. The
/// silent-misalignment risk lives entirely in the row mapping
/// `output_index j → slot_base_row`. This registry encodes both:
///
/// - `output_leaf_payload_cols[j]` — the (column-stable) payload lanes;
///   identical for every `j` since columns share, retained as an
///   ergonomic accessor.
/// - `output_leaf_a_row[j]` — the row at which the `OutputLeafPermA`
///   instance for output `j` absorbs `[value, owner_hi]`.
/// - `output_leaf_b_row[j]` — the row at which `OutputLeafPermB`
///   absorbs `[owner_lo, pad]`.
///
/// Constructed via [`Self::from_layout`] (canonical) or [`Self::new`]
/// (test-only, caller-supplied slot mapping). Both validate the
/// row-side bijection.
#[derive(Debug, Clone, Copy)]
pub struct TxBodyMerkleCols {
    /// Payload lanes per output slot `j ∈ 0..MAX_OUTPUTS`.
    pub output_leaf_payload_cols: [[usize; 2]; MAX_OUTPUTS],
    /// Row carrying `OutputLeafPermA` payload `[value, owner_hi]` for
    /// output `j`.
    pub output_leaf_a_row: [usize; MAX_OUTPUTS],
    /// Row carrying `OutputLeafPermB` payload `[owner_lo, pad]` for
    /// output `j`.
    pub output_leaf_b_row: [usize; MAX_OUTPUTS],
}

impl TxBodyMerkleCols {
    /// Canonical constructor — derives the per-output row mapping from
    /// `build_instance_layout()`. Use this in production wiring; it
    /// guarantees the registry agrees with the same layout that
    /// `TxBodyMerkleAir` itself consumes, eliminating the
    /// silent-misalignment class of bugs.
    ///
    /// Bijection invariant: each output index `j ∈ 0..MAX_OUTPUTS`
    /// appears exactly once as `OutputLeafPermA { leaf_idx: j }` and
    /// exactly once as `OutputLeafPermB { leaf_idx: j }`. Asserted at
    /// construction.
    pub fn from_layout() -> Self {
        let layout = build_instance_layout();
        let mut a_row: [Option<usize>; MAX_OUTPUTS] = [None; MAX_OUTPUTS];
        let mut b_row: [Option<usize>; MAX_OUTPUTS] = [None; MAX_OUTPUTS];
        for meta in layout.iter() {
            match meta.role {
                InstanceRole::OutputLeafPermA { leaf_idx } => {
                    let j = leaf_idx as usize;
                    assert!(
                        j < MAX_OUTPUTS,
                        "OutputLeafPermA leaf_idx {j} out of range [0, {MAX_OUTPUTS})"
                    );
                    assert!(
                        a_row[j].is_none(),
                        "duplicate OutputLeafPermA for leaf_idx {j}"
                    );
                    a_row[j] = Some(meta.slot_base_row);
                }
                InstanceRole::OutputLeafPermB { leaf_idx } => {
                    let j = leaf_idx as usize;
                    assert!(
                        j < MAX_OUTPUTS,
                        "OutputLeafPermB leaf_idx {j} out of range [0, {MAX_OUTPUTS})"
                    );
                    assert!(
                        b_row[j].is_none(),
                        "duplicate OutputLeafPermB for leaf_idx {j}"
                    );
                    b_row[j] = Some(meta.slot_base_row);
                }
                _ => {}
            }
        }
        let mut output_leaf_a_row = [0usize; MAX_OUTPUTS];
        let mut output_leaf_b_row = [0usize; MAX_OUTPUTS];
        for j in 0..MAX_OUTPUTS {
            output_leaf_a_row[j] =
                a_row[j].unwrap_or_else(|| panic!("missing OutputLeafPermA for leaf_idx {j}"));
            output_leaf_b_row[j] =
                b_row[j].unwrap_or_else(|| panic!("missing OutputLeafPermB for leaf_idx {j}"));
        }
        // Row-side bijection guard: A-rows distinct, B-rows distinct,
        // A-set and B-set disjoint.
        assert_rows_distinct("output_leaf_a_row", &output_leaf_a_row);
        assert_rows_distinct("output_leaf_b_row", &output_leaf_b_row);
        for &ra in &output_leaf_a_row {
            for &rb in &output_leaf_b_row {
                assert_ne!(ra, rb, "OutputLeafPermA row {ra} collides with PermB row");
            }
        }

        let cols = build_payload_cols();
        Self {
            output_leaf_payload_cols: cols,
            output_leaf_a_row,
            output_leaf_b_row,
        }
    }

    /// Test-only / explicit-mapping constructor. `leaf_rate_slot_per_output`
    /// must be a bijection `[0..MAX_OUTPUTS) → distinct slots in [0..16)`.
    /// Production code should prefer [`Self::from_layout`].
    ///
    /// Row mapping is still derived from `build_instance_layout()` —
    /// the slot argument only feeds the column derivation, which under
    /// E.4.c-1 is column-stable anyway.
    pub fn new(leaf_rate_slot_per_output: [usize; MAX_OUTPUTS]) -> Self {
        // Bijection guard on the caller-supplied slot mapping: every
        // slot < 16 and all distinct.
        for &s in &leaf_rate_slot_per_output {
            assert!(s < 16, "leaf_rate_slot {s} out of range [0, 16)");
        }
        for i in 0..MAX_OUTPUTS {
            for k in (i + 1)..MAX_OUTPUTS {
                assert_ne!(
                    leaf_rate_slot_per_output[i], leaf_rate_slot_per_output[k],
                    "leaf_rate_slot_per_output not injective at ({i}, {k})"
                );
            }
        }
        let mut cols = [[0usize; 2]; MAX_OUTPUTS];
        let mut j = 0;
        while j < MAX_OUTPUTS {
            let slot = leaf_rate_slot_per_output[j];
            cols[j][0] = leaf_rate_payload_col(slot, 0);
            cols[j][1] = leaf_rate_payload_col(slot, 1);
            j += 1;
        }

        let canonical = Self::from_layout();
        Self {
            output_leaf_payload_cols: cols,
            output_leaf_a_row: canonical.output_leaf_a_row,
            output_leaf_b_row: canonical.output_leaf_b_row,
        }
    }
}

fn assert_rows_distinct(label: &str, rows: &[usize; MAX_OUTPUTS]) {
    for i in 0..MAX_OUTPUTS {
        for k in (i + 1)..MAX_OUTPUTS {
            assert_ne!(
                rows[i], rows[k],
                "{}: rows not distinct at ({}, {}) = {}",
                label, i, k, rows[i]
            );
        }
    }
}

fn build_payload_cols() -> [[usize; 2]; MAX_OUTPUTS] {
    // Under E.4.c-1 the column does not depend on slot; passing the
    // identity mapping is canonical and keeps the construction
    // independent of any caller-side slot choice.
    let mut cols = [[0usize; 2]; MAX_OUTPUTS];
    let mut j = 0;
    while j < MAX_OUTPUTS {
        cols[j][0] = leaf_rate_payload_col(j, 0);
        cols[j][1] = leaf_rate_payload_col(j, 1);
        j += 1;
    }
    cols
}

/// `FriStateOpenAir` — per-input opened state lanes. Input `i` lives
/// on row `i`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FriStateOpenCols {
    pub value: [Cell; FRI_STATE_OPEN_N_INPUTS],
    pub owner_hi: [Cell; FRI_STATE_OPEN_N_INPUTS],
    pub owner_lo: [Cell; FRI_STATE_OPEN_N_INPUTS],
}

impl FriStateOpenCols {
    pub const fn new() -> Self {
        let mut value = [Cell::new(0, 0); FRI_STATE_OPEN_N_INPUTS];
        let mut owner_hi = [Cell::new(0, 0); FRI_STATE_OPEN_N_INPUTS];
        let mut owner_lo = [Cell::new(0, 0); FRI_STATE_OPEN_N_INPUTS];
        let mut i = 0;
        while i < FRI_STATE_OPEN_N_INPUTS {
            value[i] = Cell::new(COL_VALUE, i);
            owner_hi[i] = Cell::new(COL_OWNER_HI, i);
            owner_lo[i] = Cell::new(COL_OWNER_LO, i);
            i += 1;
        }
        Self {
            value,
            owner_hi,
            owner_lo,
        }
    }
}

impl Default for FriStateOpenCols {
    fn default() -> Self {
        Self::new()
    }
}

/// `FriStateCombinerComposite` — Stage 6 PI-pin destinations for
/// `prev_state_root` and `new_state_root`. The digest lanes are the
/// first two state columns of each side's output perm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CombinerCompositeCols {
    pub prev_digest_hi: usize,
    pub prev_digest_lo: usize,
    pub new_digest_hi: usize,
    pub new_digest_lo: usize,
}

impl CombinerCompositeCols {
    pub const fn new() -> Self {
        Self {
            prev_digest_hi: COMBINER_COMPOSITE_PREV_OFFSET + COMBINER_PERM_LAYOUT.s,
            prev_digest_lo: COMBINER_COMPOSITE_PREV_OFFSET + COMBINER_PERM_LAYOUT.s + 1,
            new_digest_hi: COMBINER_COMPOSITE_NEW_OFFSET + COMBINER_PERM_LAYOUT.s,
            new_digest_lo: COMBINER_COMPOSITE_NEW_OFFSET + COMBINER_PERM_LAYOUT.s + 1,
        }
    }
}

impl Default for CombinerCompositeCols {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_validity_registry_per_input_rows() {
        let r = TxValidityCols::new();
        for i in 0..MAX_INPUTS {
            assert_eq!(r.auth_tag_hi[i].row, i);
            assert_eq!(r.auth_tag_lo[i].row, i);
            assert_eq!(r.auth_tag_hi[i].col, TxValidityCol::AuthTagHi.index());
            assert_eq!(r.auth_tag_lo[i].col, TxValidityCol::AuthTagLo.index());
        }
    }

    #[test]
    fn fri_state_open_registry_per_input_rows() {
        let r = FriStateOpenCols::new();
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            assert_eq!(r.owner_hi[i], Cell::new(COL_OWNER_HI, i));
            assert_eq!(r.owner_lo[i], Cell::new(COL_OWNER_LO, i));
            assert_eq!(r.value[i], Cell::new(COL_VALUE, i));
        }
    }

    #[test]
    fn tx_body_merkle_from_layout_is_stable() {
        // Stability invariant: two independent calls to `from_layout()`
        // must produce identical row mappings. This guards against any
        // future non-determinism in `build_instance_layout()`.
        let a = TxBodyMerkleCols::from_layout();
        let b = TxBodyMerkleCols::from_layout();
        assert_eq!(a.output_leaf_a_row, b.output_leaf_a_row);
        assert_eq!(a.output_leaf_b_row, b.output_leaf_b_row);
        assert_eq!(a.output_leaf_payload_cols, b.output_leaf_payload_cols);
    }

    #[test]
    fn tx_body_merkle_from_layout_rows_are_bijection() {
        // Bijection invariant: every output index maps to a unique
        // PermA row, a unique PermB row, and the two row sets are
        // disjoint. `from_layout()` itself asserts these — this test
        // pins the invariant as a regression target.
        let r = TxBodyMerkleCols::from_layout();
        let mut seen_a = std::collections::HashSet::new();
        let mut seen_b = std::collections::HashSet::new();
        for j in 0..MAX_OUTPUTS {
            assert!(seen_a.insert(r.output_leaf_a_row[j]));
            assert!(seen_b.insert(r.output_leaf_b_row[j]));
        }
        assert!(seen_a.is_disjoint(&seen_b));
    }

    #[test]
    fn tx_body_merkle_payload_col_is_slot_independent() {
        // Under E.4.c-1 collapse, the payload column is the same for
        // every leaf-rate slot. Document the invariant and pin it as a
        // test so the registry's silent column-stability assumption
        // cannot regress.
        let canonical = TxBodyMerkleCols::from_layout();
        let lane_0 = canonical.output_leaf_payload_cols[0][0];
        let lane_1 = canonical.output_leaf_payload_cols[0][1];
        for j in 1..MAX_OUTPUTS {
            assert_eq!(canonical.output_leaf_payload_cols[j][0], lane_0);
            assert_eq!(canonical.output_leaf_payload_cols[j][1], lane_1);
        }
        assert_ne!(lane_0, lane_1);
    }

    #[test]
    #[should_panic(expected = "not injective")]
    fn tx_body_merkle_new_rejects_duplicate_slot() {
        let mut slots = [0usize; MAX_OUTPUTS];
        for j in 0..MAX_OUTPUTS {
            slots[j] = j;
        }
        slots[3] = slots[1]; // collision
        let _ = TxBodyMerkleCols::new(slots);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn tx_body_merkle_new_rejects_oob_slot() {
        let mut slots = [0usize; MAX_OUTPUTS];
        for j in 0..MAX_OUTPUTS {
            slots[j] = j;
        }
        slots[0] = 16; // out of [0, 16)
        let _ = TxBodyMerkleCols::new(slots);
    }

    #[test]
    fn combiner_composite_registry_non_overlapping() {
        let r = CombinerCompositeCols::new();
        assert_ne!(r.prev_digest_hi, r.new_digest_hi);
        assert_ne!(r.prev_digest_lo, r.new_digest_lo);
        assert_eq!(r.prev_digest_lo, r.prev_digest_hi + 1);
        assert_eq!(r.new_digest_lo, r.new_digest_hi + 1);
    }
}
