// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `TxBodySpineComposite` — Stage 1.5 composite trace stub.
//!
//! Stitches `TxValidityAir::new_3b4_with_skeleton_selector_pins(13)`
//! (log_rows lifted 8 → 13, variant B2 block-then-mask per
//! `CRYPTO.md §Stage 1.5`) with
//! `TxBodyMerkleAir::new_with_boundary_pins(pins)` into a single AIR at
//! `log_rows = 13`. Stage 1.5 is design-freeze only: this module
//! delivers the column layout, the trace builder, and the declared
//! `TxvLiveMask` public column, but introduces zero new cross-AIR
//! constraints. Stage 1b consumes `TxvLiveMask` to gate O1 leaf-payload
//! pins.
//!
//! # Column layout
//!
//! - `[0, TX_VALIDITY_3B4_PINNED_N_COLS)` → TxValidity block
//!   (width 78, constraints reference these indices unchanged).
//! - `[TX_BODY_MERKLE_COL_OFFSET, TX_BODY_MERKLE_COL_OFFSET + *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS)`
//!   → TxBodyMerkle block, native constraint indices shifted by
//!   `TX_BODY_MERKLE_COL_OFFSET`.
//! - tail column → `TxvLiveMask` `PublicColumn`.
//!
//! # Soundness
//!
//! Each sub-AIR's constraint set is sound at `log_rows = 13` without
//! modification:
//!
//! - TxValidity: every constraint is parametrized by `log_rows`, and
//!   its balance-selector / skeleton-selector programmes already
//!   zero-extend past row 12. Dead rows carry zero witness values and
//!   every constraint self-zeroes there.
//! - TxBodyMerkle: its native `log_rows = 13`, so the column-shift is
//!   the only transformation.
//!
//! Stage 2(b) implements the cross-AIR tx-body payload tie via four
//! additional `PublicColumn` declarations on TxValidity's tx-body
//! witness columns (`SlotIndex`, `Value`, `OwnerHi`, `OwnerLo`). The
//! programmes are derived from the same
//! `TxBodyMerkleBoundaryPins.{input,output}_leaf_absorb` scalars that
//! Stage 1b already binds into the Merkle side. Because both sides
//! reduce to the same verifier-known programmes, the cross-AIR
//! consistency is closed by defence-in-depth rather than a cross-row
//! indicator: no new gates, no new witness columns, and `TxvLiveMask`
//! is not needed as a gate selector (the dead tail is pinned to zero
//! by the programme itself).

use crate::airs::tx_body_merkle::{
    build_tx_body_merkle_trace_with_boundary_pins,
    emit_tx_body_merkle_constraints_with_boundary_pins,
    emit_tx_body_merkle_public_columns_with_boundary_pins,
    tx_body_merkle_column_domains_with_boundary_pins, TxBodyMerkleBoundaryPins,
    TXBODY_MERKLE_LOG_ROWS, TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS, TXBODY_MERKLE_N_PERMS,
};
use crate::airs::tx_validity::{TxValidityAir, TxValidityCol, TX_VALIDITY_3B4_PINNED_N_COLS};
use crate::gates::PublicColumn;
use crate::{Air, ColumnDomain, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::{Block128, TowerField};
use noid_tx::types::TxBody;
use noid_tx::{MAX_INPUTS, MAX_OUTPUTS};

/// Column offset of the TxValidity block inside the composite. Zero by
/// convention so TxValidity's native column indices round-trip.
pub const TXV_COL_OFFSET: usize = 0;

/// Column offset of the TxBodyMerkle block inside the composite.
/// TxValidity occupies `[0, TX_VALIDITY_3B4_PINNED_N_COLS)`.
pub const TX_BODY_MERKLE_COL_OFFSET: usize = TX_VALIDITY_3B4_PINNED_N_COLS;

/// Native rows count for `TxValidityAir` at its Stage-3b-4 floor
/// (`log_rows = 8`). Composite rows `[0, TXV_LIVE_ROWS)` carry live
/// TxValidity witness; rows `[TXV_LIVE_ROWS, 2^13)` are the B2 dead
/// tail.
pub const TXV_LIVE_ROWS: usize = 1 << 8;

/// Composite `log_rows`, fixed to the TxBodyMerkle native value.
pub const SPINE_LOG_ROWS: usize = TXBODY_MERKLE_LOG_ROWS;

/// Wraps an existing `Constraint` with a uniform column offset applied
/// to both `columns()` and `shifted_columns()`. `evaluate` forwards the
/// projected `EvalFrame` unchanged: the checker pre-projects
/// `frame.local[i] = trace[columns()[i]][row]`, so shifting the column
/// indices shifts the projection source while preserving the ordinal
/// position the inner gate reads at.
///
/// # Shift-invariance invariant
///
/// This adapter assumes **no shipped gate reads absolute column
/// indices from inside `evaluate` / `evaluate_flat`**. Every gate in
/// `noid_air::gates` (and every downstream `emit_*` gate built from
/// them) reads `frame.local[i]` / `frame.next[i]` by ordinal position
/// in `columns()` / `shifted_columns()`. The same invariant is
/// required by `CompositeAir` in `lib.rs`; a gate that violates it
/// would silently break either mechanism.
///
/// Inner range is validated at construction time: `inner.columns()`
/// and `inner.shifted_columns()` must all lie in
/// `[0, inner_n_cols)`. This catches accidental absolute indexing
/// the moment a composite is assembled rather than at evaluation.
struct ShiftedColumnsConstraint {
    inner: Box<dyn Constraint>,
    shifted_cols: Vec<usize>,
    shifted_next: Vec<usize>,
}

impl ShiftedColumnsConstraint {
    fn new(inner: Box<dyn Constraint>, offset: usize, inner_n_cols: usize) -> Self {
        for &c in inner.columns() {
            assert!(
                c < inner_n_cols,
                "ShiftedColumnsConstraint: inner local column {c} out of inner range [0, {inner_n_cols}); likely absolute indexing in source gate"
            );
        }
        for &c in inner.shifted_columns() {
            assert!(
                c < inner_n_cols,
                "ShiftedColumnsConstraint: inner shifted column {c} out of inner range [0, {inner_n_cols}); likely absolute indexing in source gate"
            );
        }
        let shifted_cols = inner.columns().iter().map(|&c| c + offset).collect();
        let shifted_next = inner
            .shifted_columns()
            .iter()
            .map(|&c| c + offset)
            .collect();
        Self {
            inner,
            shifted_cols,
            shifted_next,
        }
    }
}

impl Constraint for ShiftedColumnsConstraint {
    fn degree(&self) -> usize {
        self.inner.degree()
    }
    fn columns(&self) -> &[usize] {
        &self.shifted_cols
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted_next
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        self.inner.evaluate(frame)
    }
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        self.inner.evaluate_flat(frame)
    }
}

/// Stage 2(b) — programme for one of the four TxValidity tx-body
/// witness columns (`SlotIndex`, `Value`, `OwnerHi`, `OwnerLo`),
/// derived from `TxBodyMerkleBoundaryPins.{input,output}_leaf_absorb`.
///
/// Layout on composite rows (native `TxValidityAir::build_trace_3b4`
/// places tx-body fields on rows `[0, MAX_INPUTS)` and
/// `[MAX_INPUTS, MAX_INPUTS + MAX_OUTPUTS)`; dead tail is zero):
///
/// - `SlotIndex`: input row `i` carries `input_leaf_absorb[i][0]`
///   (= `slot_index` as a field). Non-input rows: zero.
/// - `Value`: input row `i` carries `input_leaf_absorb[i][1]`;
///   output row `MAX_INPUTS + j` carries `output_leaf_absorb[j][0]`.
/// - `OwnerHi`: input row `i` carries `input_leaf_absorb[i][2]`;
///   output row `MAX_INPUTS + j` carries `output_leaf_absorb[j][1]`.
/// - `OwnerLo`: input row `i` carries `input_leaf_absorb[i][3]`;
///   output row `MAX_INPUTS + j` carries `output_leaf_absorb[j][2]`.
///
/// Lane ordering matches `noid_poseidon2b::primitives::hash_input_leaf`
/// (`[slot, value, owner_hi, owner_lo]`) and
/// `hash_output_leaf` / `hash_utxo_leaf` (`[value, owner_hi,
/// owner_lo]`).
fn txv_tx_body_col_programme(col: TxValidityCol, pins: &TxBodyMerkleBoundaryPins) -> Vec<Block128> {
    let total = 1usize << SPINE_LOG_ROWS;
    let mut out = vec![Block128::ZERO; total];
    match col {
        TxValidityCol::SlotIndex => {
            for i in 0..MAX_INPUTS {
                out[i] = pins.input_leaf_absorb[i][0];
            }
        }
        TxValidityCol::Value => {
            for i in 0..MAX_INPUTS {
                out[i] = pins.input_leaf_absorb[i][1];
            }
            for j in 0..MAX_OUTPUTS {
                out[MAX_INPUTS + j] = pins.output_leaf_absorb[j][0];
            }
        }
        TxValidityCol::OwnerHi => {
            for i in 0..MAX_INPUTS {
                out[i] = pins.input_leaf_absorb[i][2];
            }
            for j in 0..MAX_OUTPUTS {
                out[MAX_INPUTS + j] = pins.output_leaf_absorb[j][1];
            }
        }
        TxValidityCol::OwnerLo => {
            for i in 0..MAX_INPUTS {
                out[i] = pins.input_leaf_absorb[i][3];
            }
            for j in 0..MAX_OUTPUTS {
                out[MAX_INPUTS + j] = pins.output_leaf_absorb[j][2];
            }
        }
        _ => panic!("txv_tx_body_col_programme: column {col:?} is not a tx-body payload column"),
    }
    out
}

/// Stage 2(b) — emit the four `PublicColumn`s that pin TxValidity's
/// tx-body witness columns to the Stage-1b leaf-absorb pins.
pub fn emit_txv_tx_body_public_columns(pins: &TxBodyMerkleBoundaryPins) -> Vec<PublicColumn> {
    [
        TxValidityCol::SlotIndex,
        TxValidityCol::Value,
        TxValidityCol::OwnerHi,
        TxValidityCol::OwnerLo,
    ]
    .into_iter()
    .map(|col| {
        PublicColumn::new(
            TXV_COL_OFFSET + col.index(),
            txv_tx_body_col_programme(col, pins),
        )
    })
    .collect()
}

/// `TxvLiveMask` programme: ONE on `[0, TXV_LIVE_ROWS)`, ZERO on the
/// dead tail `[TXV_LIVE_ROWS, 2^SPINE_LOG_ROWS)`.
pub fn txv_live_mask_programme() -> Vec<Block128> {
    let total = 1usize << SPINE_LOG_ROWS;
    let mut out = vec![Block128::ZERO; total];
    for r in 0..TXV_LIVE_ROWS {
        out[r] = Block128::ONE;
    }
    out
}

/// Column index of `TxvLiveMask` inside the composite trace.
pub fn txv_live_mask_col() -> usize {
    TX_BODY_MERKLE_COL_OFFSET + *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS
}

/// Total composite column count.
pub fn spine_n_cols() -> usize {
    txv_live_mask_col() + 1
}

/// Stage 1.5 composite AIR. See module docs.
pub struct TxBodySpineComposite {
    n_cols: usize,
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
    boundary_pins: TxBodyMerkleBoundaryPins,
}

impl TxBodySpineComposite {
    /// Build the composite from the Stage-1 boundary pins.
    /// `log_rows = 13` shared; TxValidity lifted to the same shape via
    /// `new_3b4_with_skeleton_selector_pins(13)`.
    pub fn new(pins: TxBodyMerkleBoundaryPins) -> Self {
        let txv_air = TxValidityAir::new_3b4_with_skeleton_selector_pins(SPINE_LOG_ROWS);
        assert_eq!(
            txv_air.n_columns(),
            TX_VALIDITY_3B4_PINNED_N_COLS,
            "TxValidityAir::new_3b4_with_skeleton_selector_pins width drifted from TX_VALIDITY_3B4_PINNED_N_COLS"
        );
        assert_eq!(txv_air.log_rows(), SPINE_LOG_ROWS);
        let (txv_constraints, txv_publics) = txv_air.into_parts();

        let merkle_n_cols = *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS;

        // Composite isolation invariant: the TxValidity block
        // [0, TX_VALIDITY_3B4_PINNED_N_COLS) and the TxBodyMerkle block
        // [TX_BODY_MERKLE_COL_OFFSET, TX_BODY_MERKLE_COL_OFFSET + merkle_n_cols)
        // do not overlap, and the TxvLiveMask column sits strictly
        // past the TxBodyMerkle block. Any future column added to
        // either sub-AIR must preserve this layout or Stage 1b's
        // cross-AIR pins lose their ground truth.
        assert_eq!(
            TXV_COL_OFFSET, 0,
            "TxValidity block must start at composite column 0"
        );
        assert_eq!(
            TX_BODY_MERKLE_COL_OFFSET, TX_VALIDITY_3B4_PINNED_N_COLS,
            "TxBodyMerkle offset must equal TxValidity width (block disjointness)"
        );
        let mask_col = txv_live_mask_col();
        assert_eq!(
            mask_col,
            TX_BODY_MERKLE_COL_OFFSET + merkle_n_cols,
            "TxvLiveMask must sit immediately after the TxBodyMerkle block"
        );

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // TxValidity block — TXV_COL_OFFSET = 0 so native indices pass
        // through. Route through the wrapper for uniformity; at
        // offset 0 the wrapper is bit-identical to a direct forward.
        // Inner range bound: TX_VALIDITY_3B4_PINNED_N_COLS.
        for c in txv_constraints {
            constraints.push(Box::new(ShiftedColumnsConstraint::new(
                c,
                TXV_COL_OFFSET,
                TX_VALIDITY_3B4_PINNED_N_COLS,
            )));
        }
        for pc in txv_publics {
            assert!(
                pc.col < TX_VALIDITY_3B4_PINNED_N_COLS,
                "TxValidity public column {} escapes inner range",
                pc.col
            );
            public_columns.push(PublicColumn::new(pc.col + TXV_COL_OFFSET, pc.values));
        }

        // TxBodyMerkle block — shifted by TX_BODY_MERKLE_COL_OFFSET.
        // Inner range bound: *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS.
        let merkle_constraints = emit_tx_body_merkle_constraints_with_boundary_pins(&pins);
        let merkle_publics = emit_tx_body_merkle_public_columns_with_boundary_pins(&pins);
        for c in merkle_constraints {
            constraints.push(Box::new(ShiftedColumnsConstraint::new(
                c,
                TX_BODY_MERKLE_COL_OFFSET,
                merkle_n_cols,
            )));
        }
        for pc in merkle_publics {
            assert!(
                pc.col < merkle_n_cols,
                "TxBodyMerkle public column {} escapes inner range",
                pc.col
            );
            public_columns.push(PublicColumn::new(
                pc.col + TX_BODY_MERKLE_COL_OFFSET,
                pc.values,
            ));
        }

        // Stage 2(b) — cross-AIR tx-body payload tie. The four TxValidity
        // tx-body witness columns (`SlotIndex`, `Value`, `OwnerHi`,
        // `OwnerLo`) are pinned directly to the same
        // `input_leaf_absorb` / `output_leaf_absorb` scalars the
        // Merkle-side Stage 1b programmes consume. Both sides thus bind
        // to the same verifier-known pins — cross-AIR consistency is
        // closed by defence-in-depth, not by a cross-row indicator.
        //
        // The programmes are zero on the TxValidity dead tail
        // (`[MAX_INPUTS + MAX_OUTPUTS, 2^SPINE_LOG_ROWS)`) because the
        // honest trace is zero there; no `TxvLiveMask` gating is
        // required.
        public_columns.extend(emit_txv_tx_body_public_columns(&pins));

        // TxvLiveMask — declared; used by the Stage 1.5 skeleton
        // invariants and kept available for any later stage that
        // needs row-domain gating (Stage 3+ cross-sub-circuit ties).
        public_columns.push(PublicColumn::new(mask_col, txv_live_mask_programme()));

        // Final alignment check: every constraint column ∈ [0, n_cols),
        // every public column ∈ [0, n_cols) and distinct block-slot
        // membership. Cheap; runs once per composite construction.
        let n_cols = spine_n_cols();
        for c in &constraints {
            for &j in c.columns() {
                assert!(j < n_cols, "constraint local col {j} >= n_cols");
            }
            for &j in c.shifted_columns() {
                assert!(j < n_cols, "constraint shifted col {j} >= n_cols");
            }
        }
        for pc in &public_columns {
            assert!(pc.col < n_cols, "public col {} >= n_cols", pc.col);
        }

        Self {
            n_cols: spine_n_cols(),
            constraints,
            public_columns,
            boundary_pins: pins,
        }
    }

    pub fn boundary_pins(&self) -> &TxBodyMerkleBoundaryPins {
        &self.boundary_pins
    }

    /// Stitch a composite trace from the caller-supplied TxValidity
    /// witness triple (body + balance view) and the TxBodyMerkle input
    /// chain. No cross-AIR consistency pinning happens here — that is
    /// the job of Stage 1b.
    pub fn build_trace(
        &self,
        body: &TxBody,
        balance_inputs: [u64; 4],
        balance_outputs: [u64; 8],
        balance_fee: u64,
        merkle_inputs: &[[Block128; 4]; TXBODY_MERKLE_N_PERMS],
    ) -> Trace {
        let txv_trace = TxValidityAir::build_trace_3b4_with_skeleton_pins(
            body,
            balance_inputs,
            balance_outputs,
            balance_fee,
            SPINE_LOG_ROWS,
        );
        assert_eq!(txv_trace.columns.len(), TX_VALIDITY_3B4_PINNED_N_COLS);

        let merkle_cols =
            build_tx_body_merkle_trace_with_boundary_pins(merkle_inputs, &self.boundary_pins);
        let merkle_domains = tx_body_merkle_column_domains_with_boundary_pins();
        assert_eq!(merkle_cols.len(), *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS);
        assert_eq!(
            merkle_domains.len(),
            *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS
        );

        let total_rows = 1usize << SPINE_LOG_ROWS;
        let mut cols = txv_trace.columns;
        let mut domains = txv_trace.domains;
        cols.extend(merkle_cols.into_iter());
        domains.extend(merkle_domains.into_iter());

        cols.push(txv_live_mask_programme());
        domains.push(ColumnDomain::Bit);

        for col in &cols {
            debug_assert_eq!(col.len(), total_rows);
        }
        assert_eq!(cols.len(), self.n_cols);

        Trace::new_with_domains(cols, domains)
    }
}

impl Air for TxBodySpineComposite {
    fn n_columns(&self) -> usize {
        self.n_cols
    }
    fn log_rows(&self) -> usize {
        SPINE_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
    fn public_columns(&self) -> &[PublicColumn] {
        &self.public_columns
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::tx_body_merkle::{
        build_instance_layout, InstanceRole, N_ROUNDS, TXBODY_MERKLE_LAYOUT,
    };

    fn empty_tx_body() -> TxBody {
        TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Derive an internally-consistent `(pins, merkle_inputs)` pair by
    /// running the honest permutation chain with zero seeds (so
    /// `prev_state_root = fee_leaf = ZERO`) and reading back the wrap
    /// output as the `tx_body_hash`.
    fn build_honest_pins_and_inputs() -> (
        TxBodyMerkleBoundaryPins,
        Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
    ) {
        let inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
            Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);

        let placeholder = TxBodyMerkleBoundaryPins::default();
        let merkle_cols = build_tx_body_merkle_trace_with_boundary_pins(&inputs, &placeholder);

        let layout = build_instance_layout();
        let wrap_meta = layout
            .iter()
            .find(|m| matches!(m.role, InstanceRole::WrapPerm))
            .expect("wrap instance present");
        let wrap_out_row = wrap_meta.slot_base_row + N_ROUNDS;
        let s0 = merkle_cols[TXBODY_MERKLE_LAYOUT.s][wrap_out_row];
        let s1 = merkle_cols[TXBODY_MERKLE_LAYOUT.s + 1][wrap_out_row];

        let pins = TxBodyMerkleBoundaryPins {
            tx_body_hash: [s0, s1],
            ..TxBodyMerkleBoundaryPins::default()
        };
        (pins, inputs)
    }

    #[test]
    fn composite_layout_constants() {
        assert_eq!(TXV_COL_OFFSET, 0);
        assert_eq!(TX_BODY_MERKLE_COL_OFFSET, TX_VALIDITY_3B4_PINNED_N_COLS);
        assert_eq!(TX_BODY_MERKLE_COL_OFFSET, 78);
        assert_eq!(SPINE_LOG_ROWS, 13);
        assert_eq!(TXV_LIVE_ROWS, 256);
        let n = spine_n_cols();
        assert_eq!(
            n,
            TX_VALIDITY_3B4_PINNED_N_COLS + *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS + 1
        );
    }

    #[test]
    fn txv_live_mask_programme_shape() {
        let m = txv_live_mask_programme();
        assert_eq!(m.len(), 1 << SPINE_LOG_ROWS);
        for r in 0..TXV_LIVE_ROWS {
            assert_eq!(m[r], Block128::ONE, "live row {r}");
        }
        for r in TXV_LIVE_ROWS..(1 << SPINE_LOG_ROWS) {
            assert_eq!(m[r], Block128::ZERO, "dead row {r}");
        }
    }

    #[test]
    fn honest_round_trip_accepts() {
        let (pins, merkle_inputs) = build_honest_pins_and_inputs();
        let spine = TxBodySpineComposite::new(pins);

        let body = empty_tx_body();
        let trace = spine.build_trace(&body, [0u64; 4], [0u64; 8], 0u64, &merkle_inputs);
        assert_eq!(trace.n_cols(), spine.n_columns());
        assert_eq!(trace.log_rows, spine.log_rows());
        assert!(spine.check(&trace), "honest composite trace must accept");
    }

    #[test]
    fn stage_1a_wrap_tamper_still_rejects_in_composite() {
        let (pins, merkle_inputs) = build_honest_pins_and_inputs();
        let spine = TxBodySpineComposite::new(pins);

        let body = empty_tx_body();
        let mut trace = spine.build_trace(&body, [0u64; 4], [0u64; 8], 0u64, &merkle_inputs);

        let layout = build_instance_layout();
        let wrap = layout
            .iter()
            .find(|m| matches!(m.role, InstanceRole::WrapPerm))
            .unwrap();
        let col = TX_BODY_MERKLE_COL_OFFSET + TXBODY_MERKLE_LAYOUT.s;
        let row = wrap.slot_base_row + N_ROUNDS;
        trace.columns[col][row] = trace.columns[col][row] + Block128::ONE;
        assert!(
            !spine.check(&trace),
            "wrap-output tamper must reject at composite layer (Stage 1a regression)"
        );
    }

    #[test]
    fn txv_live_mask_tamper_rejects() {
        let (pins, merkle_inputs) = build_honest_pins_and_inputs();
        let spine = TxBodySpineComposite::new(pins);

        let body = empty_tx_body();
        let mut trace = spine.build_trace(&body, [0u64; 4], [0u64; 8], 0u64, &merkle_inputs);

        let col = txv_live_mask_col();
        trace.columns[col][0] = Block128::ZERO;
        assert!(
            !spine.check(&trace),
            "TxvLiveMask tamper on live row must reject"
        );
    }

    #[test]
    fn dead_tail_freedom_on_txv_block() {
        // Property: writing arbitrary junk into *any* TxValidity
        // witness column on *any* dead row (TXV_LIVE_ROWS..2^13) does
        // not cause `Air::check` to reject. This is the formal
        // statement of the B2 soundness claim in CRYPTO.md §Stage 1.5.
        //
        // Scope: non-bool TxValidity witness columns. Bool columns
        // (`InputValid`, `OutputValid`) are excluded because the
        // skeleton-selector public column for them is *also* a pin on
        // the dead tail (forbidden-rows programme covers
        // [MAX_INPUTS..2^13)), so writing `ONE` there would legitimately
        // reject. Writing ZERO passes trivially; we don't need a test
        // for that. Balance-block columns are excluded because their
        // is_input / is_reset selectors are pinned PublicColumns, so
        // junking them breaks the pin check (not the B2 claim).
        //
        // Coverage: 8 non-bool TxValidity witness columns × 64 random
        // dead rows sampled from [TXV_LIVE_ROWS, 2^13) with a mix of
        // junk values.
        let (pins, merkle_inputs) = build_honest_pins_and_inputs();
        let spine = TxBodySpineComposite::new(pins);
        let body = empty_tx_body();
        let total_rows = 1usize << SPINE_LOG_ROWS;

        // Non-bool TxValidity witness columns: SpendSecretHi=6,
        // SpendSecretLo=7, AuthTagHi=8, AuthTagLo=9.
        //
        // Stage 2(b) pinned SlotIndex=2 / Value=3 / OwnerHi=4 /
        // OwnerLo=5 as PublicColumns over the whole composite
        // (including the dead tail, which the pin forces to ZERO), so
        // they are no longer free-tail witnesses. The B2 claim still
        // holds for the remaining four columns: writing junk to any of
        // them on a dead row must not cause `Air::check` to reject.
        let non_bool_cols: [usize; 4] = [6, 7, 8, 9];
        let junk_values: [u128; 4] = [
            0xDEADBEEFu128,
            0xFFFFFFFF_FFFFFFFFu128,
            0x1u128,
            0xA5A5A5A5_5A5A5A5Au128,
        ];
        // Deterministic "random" dead rows — LCG sequence, no rand dep.
        // Small sample: each check() sweeps 2^13 rows across all
        // composite constraints, so we keep the matrix modest and
        // reuse a single baseline trace (restore cell after each poke).
        let mut rng_state: u64 = 0x9E3779B97F4A7C15;
        let mut sampled_rows: Vec<usize> = Vec::with_capacity(8);
        while sampled_rows.len() < 8 {
            rng_state = rng_state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = TXV_LIVE_ROWS + (rng_state as usize) % (total_rows - TXV_LIVE_ROWS);
            sampled_rows.push(r);
        }

        let mut trace = spine.build_trace(&body, [0u64; 4], [0u64; 8], 0u64, &merkle_inputs);
        for (trial, &row) in sampled_rows.iter().enumerate() {
            for &col_idx in &non_bool_cols {
                let col = TXV_COL_OFFSET + col_idx;
                let saved = trace.columns[col][row];
                let junk = Block128::from(junk_values[trial % junk_values.len()]);
                trace.columns[col][row] = junk;
                assert!(
                    spine.check(&trace),
                    "B2 dead-tail freedom broke: col {col_idx} row {row} trial {trial}"
                );
                trace.columns[col][row] = saved;
            }
        }
    }

    // ------------------------------------------------------------------
    // Stage 2(b) — cross-AIR tx-body payload tie
    // ------------------------------------------------------------------

    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
    use noid_tx::{TxInput, TxOutput};

    /// Build a honest `(TxBody, TxBodyMerkleBoundaryPins, merkle_inputs)`
    /// triple where the TxValidity tx-body witness columns match
    /// `pins.{input,output}_leaf_absorb`. Uses one real input + one
    /// real output (balanced, zero fee); remaining slots are dummy.
    fn honest_stage2b_fixture() -> (
        TxBody,
        TxBodyMerkleBoundaryPins,
        Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
    ) {
        let slot_index: u32 = 7;
        let value: u64 = 1234;
        let in_owner_bytes: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];
        let in_owner = Address(in_owner_bytes);
        let out_owner_bytes: [u8; 32] = [
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E,
            0x8F, 0x90, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,
            0xC3, 0xD2, 0xE1, 0xF0,
        ];
        let out_owner = Address(out_owner_bytes);

        let [in_owner_hi, in_owner_lo] = in_owner.as_fields();
        let [out_owner_hi, out_owner_lo] = out_owner.as_fields();

        // Input leaf absorb matches hash_input_leaf([slot, value, hi, lo]).
        let mut input_leaf_absorb = [[Block128::ZERO; 4]; 4];
        input_leaf_absorb[0] = [
            Block128::from(slot_index as u128),
            Block128::from(value as u128),
            in_owner_hi,
            in_owner_lo,
        ];

        // Output leaf absorb matches hash_utxo_leaf([value, hi, lo]).
        let mut output_leaf_absorb = [[Block128::ZERO; 3]; 8];
        output_leaf_absorb[0] = [Block128::from(value as u128), out_owner_hi, out_owner_lo];

        // Derive a self-consistent wrap output for the tx_body_hash pin
        // by running the trace builder once with a placeholder hash.
        let merkle_inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
            Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);
        let placeholder = TxBodyMerkleBoundaryPins {
            tx_body_hash: [Block128::ZERO; 2],
            input_leaf_absorb,
            output_leaf_absorb,
            ..TxBodyMerkleBoundaryPins::default()
        };
        let merkle_cols =
            build_tx_body_merkle_trace_with_boundary_pins(&merkle_inputs, &placeholder);
        let wrap_meta = build_instance_layout()
            .iter()
            .find(|m| matches!(m.role, InstanceRole::WrapPerm))
            .cloned()
            .expect("wrap instance present");
        let wrap_out_row = wrap_meta.slot_base_row + N_ROUNDS;
        let s0 = merkle_cols[TXBODY_MERKLE_LAYOUT.s][wrap_out_row];
        let s1 = merkle_cols[TXBODY_MERKLE_LAYOUT.s + 1][wrap_out_row];

        let pins = TxBodyMerkleBoundaryPins {
            tx_body_hash: [s0, s1],
            input_leaf_absorb,
            output_leaf_absorb,
            ..TxBodyMerkleBoundaryPins::default()
        };

        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![
                TxInput {
                    slot_index,
                    value,
                    owner: in_owner,
                    spend_secret: SpendSecret([0x22; 32]),
                    auth_tag: AuthTag([0x33; 32]),
                    valid: true,
                },
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                TxOutput {
                    value,
                    owner: out_owner,
                    valid: true,
                },
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
        };

        (body, pins, merkle_inputs)
    }

    #[test]
    fn stage_2b_declares_four_txv_tx_body_public_columns() {
        let (_body, pins, _inputs) = honest_stage2b_fixture();
        let spine = TxBodySpineComposite::new(pins);

        // Every TxValidity tx-body column must be among the composite
        // public columns at the TxValidity offset.
        let expected_cols = [
            TXV_COL_OFFSET + TxValidityCol::SlotIndex.index(),
            TXV_COL_OFFSET + TxValidityCol::Value.index(),
            TXV_COL_OFFSET + TxValidityCol::OwnerHi.index(),
            TXV_COL_OFFSET + TxValidityCol::OwnerLo.index(),
        ];
        for col in expected_cols {
            let hit = spine.public_columns().iter().any(|pc| pc.col == col);
            assert!(hit, "no PublicColumn declared for tx-body col {col}");
        }
    }

    #[test]
    fn stage_2b_accepts_honest_tx_body_witness() {
        let (body, pins, merkle_inputs) = honest_stage2b_fixture();
        let spine = TxBodySpineComposite::new(pins);
        let in_val = body.inputs[0].value;
        let out_val = body.outputs[0].value;
        let trace = spine.build_trace(
            &body,
            [in_val, 0, 0, 0],
            [out_val, 0, 0, 0, 0, 0, 0, 0],
            0,
            &merkle_inputs,
        );
        assert!(spine.check(&trace), "honest Stage 2(b) trace must accept");
    }

    #[test]
    fn stage_2b_rejects_slot_index_tamper() {
        let (body, pins, merkle_inputs) = honest_stage2b_fixture();
        let spine = TxBodySpineComposite::new(pins);
        let in_val = body.inputs[0].value;
        let out_val = body.outputs[0].value;
        let mut trace = spine.build_trace(
            &body,
            [in_val, 0, 0, 0],
            [out_val, 0, 0, 0, 0, 0, 0, 0],
            0,
            &merkle_inputs,
        );
        // Flip SlotIndex on input row 0 — pinned to input_leaf_absorb[0][0].
        let col = TXV_COL_OFFSET + TxValidityCol::SlotIndex.index();
        trace.columns[col][0] = trace.columns[col][0] + Block128::ONE;
        assert!(
            !spine.check(&trace),
            "Stage 2(b) must reject SlotIndex tamper on an input row"
        );
    }

    #[test]
    fn stage_2b_rejects_value_tamper_on_output_row() {
        let (body, pins, merkle_inputs) = honest_stage2b_fixture();
        let spine = TxBodySpineComposite::new(pins);
        let in_val = body.inputs[0].value;
        let out_val = body.outputs[0].value;
        let mut trace = spine.build_trace(
            &body,
            [in_val, 0, 0, 0],
            [out_val, 0, 0, 0, 0, 0, 0, 0],
            0,
            &merkle_inputs,
        );
        // Flip Value on output row 0 — pinned to output_leaf_absorb[0][0].
        let col = TXV_COL_OFFSET + TxValidityCol::Value.index();
        let row = MAX_INPUTS;
        trace.columns[col][row] = trace.columns[col][row] + Block128::ONE;
        assert!(
            !spine.check(&trace),
            "Stage 2(b) must reject Value tamper on an output row"
        );
    }

    #[test]
    fn stage_2b_rejects_owner_hi_tamper_on_input_row() {
        let (body, pins, merkle_inputs) = honest_stage2b_fixture();
        let spine = TxBodySpineComposite::new(pins);
        let in_val = body.inputs[0].value;
        let out_val = body.outputs[0].value;
        let mut trace = spine.build_trace(
            &body,
            [in_val, 0, 0, 0],
            [out_val, 0, 0, 0, 0, 0, 0, 0],
            0,
            &merkle_inputs,
        );
        let col = TXV_COL_OFFSET + TxValidityCol::OwnerHi.index();
        trace.columns[col][0] = trace.columns[col][0] + Block128::ONE;
        assert!(
            !spine.check(&trace),
            "Stage 2(b) must reject OwnerHi tamper on an input row"
        );
    }

    #[test]
    fn stage_2b_rejects_owner_lo_tamper_on_output_row() {
        let (body, pins, merkle_inputs) = honest_stage2b_fixture();
        let spine = TxBodySpineComposite::new(pins);
        let in_val = body.inputs[0].value;
        let out_val = body.outputs[0].value;
        let mut trace = spine.build_trace(
            &body,
            [in_val, 0, 0, 0],
            [out_val, 0, 0, 0, 0, 0, 0, 0],
            0,
            &merkle_inputs,
        );
        let col = TXV_COL_OFFSET + TxValidityCol::OwnerLo.index();
        let row = MAX_INPUTS;
        trace.columns[col][row] = trace.columns[col][row] + Block128::ONE;
        assert!(
            !spine.check(&trace),
            "Stage 2(b) must reject OwnerLo tamper on an output row"
        );
    }

    #[test]
    fn stage_2b_rejects_value_on_dead_row_tamper() {
        // Dead-tail rows of the four pinned tx-body columns are now
        // pinned to ZERO by the Stage 2(b) PublicColumn programmes.
        // Writing junk there must reject (this is what distinguishes
        // Stage 2(b) from the pre-existing B2 `dead_tail_freedom`
        // property: those 4 columns were free before, pinned now).
        let (body, pins, merkle_inputs) = honest_stage2b_fixture();
        let spine = TxBodySpineComposite::new(pins);
        let in_val = body.inputs[0].value;
        let out_val = body.outputs[0].value;
        let mut trace = spine.build_trace(
            &body,
            [in_val, 0, 0, 0],
            [out_val, 0, 0, 0, 0, 0, 0, 0],
            0,
            &merkle_inputs,
        );
        let col = TXV_COL_OFFSET + TxValidityCol::Value.index();
        let row = TXV_LIVE_ROWS + 42; // deep in the dead tail
        trace.columns[col][row] = Block128::from(0xBADu128);
        assert!(
            !spine.check(&trace),
            "Stage 2(b) pins must force dead-tail Value cells to ZERO"
        );
    }
}
