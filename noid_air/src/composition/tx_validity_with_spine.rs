// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.7 — PR B.3: spine-embedded composite with verbatim leaf-band.
//!
//! Constructs a [`crate::CompositeAir`] at `outer_log_rows = 13` that
//! embeds:
//! - the full Stage 5.6
//!   [`super::tx_validity_leaf::TxValidityCompositeLeaf`] verbatim at
//!   outer columns `[0, TX_VALIDITY_LEAF_N_COLS)` (now lifted to
//!   `outer_log_rows = 13` by PR B.2 so it co-exists with the spine
//!   without an outer-row mismatch); the leaf's bridges still point at
//!   their PI-pinned dst families (T2a / T3) — PR B.4 will atomically
//!   retarget those dsts to the spine's auth-tag and output-leaf cells
//!   and delete the now-redundant `PublicColumn` programmes.
//! - the [`crate::airs::tx_body_spine::TxBodySpineComposite`] block
//!   immediately past the leaf-band, shifted by
//!   [`SPINE_BLOCK_OUTER_BASE`] via [`ShiftedColumnsConstraint`].
//!
//! No new bridges are introduced in PR B.3; the leaf and spine remain
//! independent sub-circuits sharing only the outer column space and the
//! lifted `outer_log_rows = 13`. The spine layout
//! [`super::spine_adapter::SpineEmbeddingLayout`] is exposed so the
//! retarget in PR B.4 can resolve T2a / T3 dst cells against it.

use crate::airs::fri_state_combiner_composite::FriStateCombinerComposite;
use crate::airs::fri_state_open::{
    FriStateOpenAir, FriStateOpenWitness, FRI_STATE_OPEN_N_INPUTS,
};
use crate::airs::tx_body_merkle::{TxBodyMerkleBoundaryPins, TXBODY_MERKLE_N_PERMS};
use crate::airs::tx_body_spine::{spine_n_cols, TxBodySpineComposite, SPINE_LOG_ROWS};
use crate::composition::spine_adapter::SpineEmbeddingLayout;
use crate::composition::tx_validity_leaf::{
    native_output_leaf_hash, write_leaf_block_traces, LeafConstructionOptions, T2aDstOverride,
    T3DstOverride, TxValidityCompositeLeaf, N_OUTPUTS,
    TX_VALIDITY_LEAF_LOG_ROWS, TX_VALIDITY_LEAF_N_COLS,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, CompositeAir, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::{Block128, TowerField};
use noid_tx::TxBody;

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Outer log-rows. The spine demands `≥ SPINE_LOG_ROWS = 13` and the
/// PR-B.2 leaf composite is fixed at `13`; they coincide.
pub const TX_VALIDITY_WITH_SPINE_LOG_ROWS: usize = SPINE_LOG_ROWS;

/// Width reserved for the embedded leaf-band — exactly matches the
/// 5.6 leaf composite's column count.
pub const LEAF_BAND_RESERVED: usize = TX_VALIDITY_LEAF_N_COLS;

const _: () = {
    assert!(TX_VALIDITY_WITH_SPINE_LOG_ROWS == SPINE_LOG_ROWS);
    assert!(TX_VALIDITY_WITH_SPINE_LOG_ROWS == TX_VALIDITY_LEAF_LOG_ROWS);
};

/// Outer column at which the embedded spine block begins.
pub const SPINE_BLOCK_OUTER_BASE: usize = LEAF_BAND_RESERVED;

/// Total outer column count.
pub fn tx_validity_with_spine_n_cols() -> usize {
    SPINE_BLOCK_OUTER_BASE + spine_n_cols()
}

// ---------------------------------------------------------------------------
// Column-shift adapter (mirrors the per-composite adapter pattern from
// the 5.3 / 5.4 / 5.5 / 5.6 composites). Used only for the spine block;
// the leaf-band is embedded at outer offset 0 and its constraints carry
// over without any column shift.
// ---------------------------------------------------------------------------

struct ShiftedColumnsConstraint {
    inner: Box<dyn Constraint>,
    shifted_cols: Vec<usize>,
    shifted_next: Vec<usize>,
}

impl ShiftedColumnsConstraint {
    fn new(inner: Box<dyn Constraint>, offset: usize, inner_n_cols: usize) -> Self {
        for &c in inner.columns() {
            assert!(c < inner_n_cols, "constraint col {c} >= inner range {inner_n_cols}");
        }
        for &c in inner.shifted_columns() {
            assert!(c < inner_n_cols, "constraint shifted col {c} >= inner range {inner_n_cols}");
        }
        let shifted_cols = inner.columns().iter().map(|&c| c + offset).collect();
        let shifted_next = inner.shifted_columns().iter().map(|&c| c + offset).collect();
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

// ---------------------------------------------------------------------------
// Composite
// ---------------------------------------------------------------------------

/// Stage 5.7 PR B.3 composite: full leaf composite (verbatim) +
/// `TxBodySpineComposite` block. Both sides remain independent;
/// PR B.4 will retarget the leaf's T2a / T3 bridges to spine cells.
pub struct TxValidityCompositeWithSpine {
    pub air: CompositeAir,
    spine_layout: SpineEmbeddingLayout,
    boundary_pins: TxBodyMerkleBoundaryPins,
    pub(crate) body: TxBody,
    balance_inputs: [u64; 4],
    balance_outputs: [u64; 8],
    balance_fee: u64,
    merkle_inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
    // Leaf-band witness (consumed via `TxValidityCompositeLeaf::into_parts`).
    combiner: FriStateCombinerComposite,
    open_witness: FriStateOpenWitness,
    open_public_columns: Vec<PublicColumn>,
    secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    tx_body_hash: [Block128; 2],
    output_fields: [[Block128; 4]; N_OUTPUTS],
    /// PR B.5: per-output T3 dst cells inside the embedded spine
    /// block. The HLeaf-block bridge dst is retargeted here; the
    /// leaf-band's per-output T3 `PublicColumn` programmes are
    /// suppressed at construction.
    t3_override: [T3DstOverride; N_OUTPUTS],
    /// PR B.6: per-input T2a dst cells inside the embedded spine
    /// block, pointing at `TxValidityCol::AuthTagHi/Lo[i]`. The
    /// HAuth-block bridge dst is retargeted here; the leaf-band's
    /// per-input T2a `PublicColumn` programmes are suppressed at
    /// construction.
    t2a_override: [T2aDstOverride; FRI_STATE_OPEN_N_INPUTS],
    /// Per-input declared auth tags. PR B.6 needs these at
    /// `build_trace`-time to restore the spine `AuthTagHi/Lo` cells
    /// after the spine inner trace clobbers the leaf-band's writes.
    auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
}

impl TxValidityCompositeWithSpine {
    /// Build the composite. The leaf composite is constructed first and
    /// consumed via `into_parts()`; its constraints / publics use
    /// absolute column indices in `[0, TX_VALIDITY_LEAF_N_COLS)` and
    /// remain valid in the wider outer column space (no column shift).
    /// The spine is shifted by [`SPINE_BLOCK_OUTER_BASE`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        boundary_pins: TxBodyMerkleBoundaryPins,
        body: TxBody,
        balance_inputs: [u64; 4],
        balance_outputs: [u64; 8],
        balance_fee: u64,
        merkle_inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
        tx_body_hash: [Block128; 2],
        auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
        output_fields: [[Block128; 4]; N_OUTPUTS],
        output_leaf_hashes: [[Block128; 2]; N_OUTPUTS],
    ) -> Self {
        let outer_n_cols = tx_validity_with_spine_n_cols();
        let outer_log_rows = TX_VALIDITY_WITH_SPINE_LOG_ROWS;

        let spine_layout =
            SpineEmbeddingLayout::new(SPINE_BLOCK_OUTER_BASE, outer_n_cols, outer_log_rows)
                .expect("spine layout must fit by construction");

        // PR B.5 — atomic T3 retarget. Compute per-output dst cells
        // inside the embedded spine block and pass them to the leaf
        // composite via `LeafConstructionOptions::t3_dst_override`.
        // This (a) routes each HLeaf bridge's hi/lo dst at the spine's
        // `OutputLeafPermA{leaf_idx=j}` rate-payload row (cols
        // `output_leaf_a_outer_cell(j, 0/1)`), and (b) suppresses the
        // 5.6-era per-output `PublicColumn::pinned_row_programme`
        // emission inside the leaf composite. The spine's own air
        // imposes no constraint on these payload cells at head rows
        // (the E.4.c rate-absorb gate is gated by a single-hot
        // selector at non-head row_0; head rows are masked off).
        // `build_trace` writes `native_output_leaf_hash(output_fields[j])`
        // into these cells after the spine inner copy so they carry
        // the value the bridge ties HLeaf squeeze to.
        let mut t3_override = [T3DstOverride { hi_col: 0, hi_row: 0, lo_col: 0, lo_row: 0 };
            N_OUTPUTS];
        for j in 0..N_OUTPUTS {
            let hi = spine_layout.output_leaf_a_outer_cell(j, 0);
            let lo = spine_layout.output_leaf_a_outer_cell(j, 1);
            t3_override[j] = T3DstOverride {
                hi_col: hi.col,
                hi_row: hi.row,
                lo_col: lo.col,
                lo_row: lo.row,
            };
        }

        // PR B.6 — atomic T2a retarget. Compute per-input dst cells
        // at the spine's `TxValidityCol::AuthTagHi/Lo[i]` (composite
        // cols 8/9, row i). With an empty `TxBody`, the spine's
        // TxValidityAir build-trace leaves these cells at zero and
        // imposes no constraint on them when `InputValid[i] = 0`,
        // so `build_trace` can restore them to
        // `native_auth_tag(secrets[i], tx_body_hash)` after the
        // spine inner copy. The HAuth bridge ties each cell to the
        // HAuth squeeze; both sides equal the same MAC.
        let mut t2a_override =
            [T2aDstOverride { hi_col: 0, hi_row: 0, lo_col: 0, lo_row: 0 };
                FRI_STATE_OPEN_N_INPUTS];
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let hi = spine_layout.auth_tag_hi_outer_cell(i);
            let lo = spine_layout.auth_tag_lo_outer_cell(i);
            t2a_override[i] = T2aDstOverride {
                hi_col: hi.col,
                hi_row: hi.row,
                lo_col: lo.col,
                lo_row: lo.row,
            };
        }

        // PR B.7 — reverted. HAuth's `pre_s_B[lane]@N_ROUNDS` bridge
        // src carries `A.s[lane] + tx_body_hash[lane]` (per the
        // B-absorb gate `A.s + pre_s_B + tx_body == 0`), not a bare
        // `tx_body_hash`, so it cannot be tied to the spine's
        // wrap-output cell (which carries `tx_body_hash`). The
        // cross-AIR "same tx_body_hash everywhere" invariant is
        // enforced by the B-absorb gate baking `tx_body_hash` in as
        // a construction-time constant (HAuthAir) and by the Merkle
        // wrap-output pinning the same scalar via boundary pins;
        // no bridge required. T2b stays on the 5.6 per-input unpinned
        // dst cells inside the leaf band.

        // Build the leaf composite and consume it for its constraints /
        // publics + witness pieces required to rebuild the leaf-band
        // sub-trace.
        let leaf = TxValidityCompositeLeaf::new_with_options(
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
            output_fields,
            output_leaf_hashes,
            LeafConstructionOptions {
                t3_dst_override: Some(t3_override),
                t2a_dst_override: Some(t2a_override),
                t2b_dst_override: None,
            },
        );
        let (
            leaf_air,
            combiner,
            open_witness,
            open_public_columns,
            secrets,
            tx_body_hash,
            auth_tags,
            output_fields,
            _output_leaf_hashes,
        ) = leaf.into_parts();
        let (leaf_log_rows, leaf_n_cols, leaf_constraints, leaf_publics) = leaf_air.into_parts();
        assert_eq!(leaf_log_rows, outer_log_rows);
        assert_eq!(leaf_n_cols, LEAF_BAND_RESERVED);

        // Build the spine and harvest its constraints / publics.
        let spine = TxBodySpineComposite::new(boundary_pins);
        let (spine_n, spine_constraints, spine_publics, _pins_dup) = spine.into_parts();
        assert_eq!(spine_n, spine_n_cols());

        let mut constraints: Vec<Box<dyn Constraint>> =
            Vec::with_capacity(leaf_constraints.len() + spine_constraints.len());
        let mut public_columns: Vec<PublicColumn> =
            Vec::with_capacity(leaf_publics.len() + spine_publics.len());

        // Leaf-band: no column shift (offset 0).
        for c in leaf_constraints {
            constraints.push(c);
        }
        for pc in leaf_publics {
            public_columns.push(pc);
        }

        // Spine: shift by `SPINE_BLOCK_OUTER_BASE`.
        let block_base = spine_layout.block_base();
        for c in spine_constraints {
            constraints.push(Box::new(ShiftedColumnsConstraint::new(c, block_base, spine_n)));
        }
        for pc in spine_publics {
            assert!(pc.col < spine_n);
            public_columns.push(PublicColumn::new(pc.col + block_base, pc.values));
        }

        let air = CompositeAir::from_parts_with_publics(
            outer_log_rows,
            outer_n_cols,
            constraints,
            public_columns,
        );

        Self {
            air,
            spine_layout,
            boundary_pins,
            body,
            balance_inputs,
            balance_outputs,
            balance_fee,
            merkle_inputs,
            combiner,
            open_witness,
            open_public_columns,
            secrets,
            tx_body_hash,
            output_fields,
            t3_override,
            t2a_override,
            auth_tags,
        }
    }

    /// Stitch the outer trace: leaf-band sub-traces, then the spine
    /// inner trace, then a final pass overwriting every public column
    /// with its programme.
    pub fn build_trace(&self) -> Trace {
        let outer_n_cols = tx_validity_with_spine_n_cols();
        let outer_n_rows = 1usize << TX_VALIDITY_WITH_SPINE_LOG_ROWS;

        let mut cols: Vec<Vec<Block128>> = (0..outer_n_cols)
            .map(|_| vec![Block128::ZERO; outer_n_rows])
            .collect();

        // Leaf-band. The leaf composite was built with
        // `t3_dst_override = Some(self.t3_override)`, so the inner
        // HLeaf-block trace writer also routes its dst writes there.
        // These writes will be clobbered by the spine inner copy below
        // and then restored explicitly.
        write_leaf_block_traces(
            &mut cols,
            &self.combiner,
            &self.open_witness,
            &self.open_public_columns,
            &self.secrets,
            self.tx_body_hash,
            &self.output_fields,
            outer_n_cols,
            TX_VALIDITY_WITH_SPINE_LOG_ROWS,
            Some(self.t3_override),
            Some(self.t2a_override),
            None,
        );

        // Spine block.
        let inner = TxBodySpineComposite::new(self.boundary_pins).build_trace(
            &self.body,
            self.balance_inputs,
            self.balance_outputs,
            self.balance_fee,
            &self.merkle_inputs,
        );
        let inner_cols = inner.columns;
        assert_eq!(inner_cols.len(), spine_n_cols());
        for col in &inner_cols {
            debug_assert_eq!(col.len(), outer_n_rows);
        }
        let block_base = self.spine_layout.block_base();
        for (i, src) in inner_cols.into_iter().enumerate() {
            cols[block_base + i] = src;
        }

        // PR B.5 — restore the per-output T3 dst cells inside the spine
        // block. These cells live on `leaf_rate_payload_col` columns at
        // `OutputLeafPermA{leaf_idx=j}` rows; the spine's E.4.c
        // rate-absorb gate is gated by a single-hot selector that
        // fires only at non-head row_0s, so writing
        // `native_output_leaf_hash(output_fields[j])` into these
        // (head-row) cells does not violate any spine constraint.
        // The HLeaf bridge ties each cell to the HLeaf squeeze; the
        // squeeze carries the same `native_output_leaf_hash(...)`,
        // closing audit § 6.1's T3 retarget contract.
        for j in 0..N_OUTPUTS {
            let leaf_hash = native_output_leaf_hash(self.output_fields[j]);
            let dst = &self.t3_override[j];
            cols[dst.hi_col][dst.hi_row] = leaf_hash[0];
            cols[dst.lo_col][dst.lo_row] = leaf_hash[1];
        }

        // PR B.6 / PR D.2a — restore the per-input T2a dst cells.
        // Dummy slot: spine left cell at zero and the
        // `InputValid[i] * (auth_tag - MAC) == 0` gate is vacuous, so
        // we overwrite with the declared MAC.
        // Live slot: spine already wrote `input.auth_tag.as_fields()`
        // and its MAC gate enforces the cell equals
        // `native_auth_tag(secret_i, tx_body_hash) == self.auth_tags[i]`.
        // We assert coincidence instead of blindly overwriting —
        // defence-in-depth: both gates see the same honest cell.
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let dst = &self.t2a_override[i];
            let is_live = self
                .body
                .inputs
                .get(i)
                .map_or(false, |inp| inp.valid);
            if is_live {
                assert_eq!(
                    cols[dst.hi_col][dst.hi_row], self.auth_tags[i][0],
                    "input {i}: spine-written AuthTagHi must equal native MAC",
                );
                assert_eq!(
                    cols[dst.lo_col][dst.lo_row], self.auth_tags[i][1],
                    "input {i}: spine-written AuthTagLo must equal native MAC",
                );
            } else {
                cols[dst.hi_col][dst.hi_row] = self.auth_tags[i][0];
                cols[dst.lo_col][dst.lo_row] = self.auth_tags[i][1];
            }
        }

        // Final pass: overwrite every declared public column with its
        // programme.
        for pc in self.air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }

        Trace::new(cols)
    }

    pub fn air(&self) -> &CompositeAir {
        &self.air
    }

    pub fn spine_layout(&self) -> &SpineEmbeddingLayout {
        &self.spine_layout
    }

    pub fn boundary_pins(&self) -> &TxBodyMerkleBoundaryPins {
        &self.boundary_pins
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Stage 5.7 honest fixture — exposed for the `noid_stark`
/// `prove_air`/`verify_air` round-trip integration test. The
/// fixture is identical to the in-module `build_honest()` used by
/// unit tests below. Not part of the public surface; marked
/// `#[doc(hidden)]`.
#[doc(hidden)]
pub fn build_stage_5_7_honest_fixture() -> TxValidityCompositeWithSpine {
    fixture::build_honest()
}

#[doc(hidden)]
pub mod fixture {
    use super::*;
    use crate::airs::fri_state_combiner::{
        build_combiner_side_trace, extract_combiner_digest_fields, FriStateCombinerPreimage,
        COMBINER_PERM_LAYOUT,
    };
    use crate::airs::fri_state_open::FriStateOpenClaim;
    use crate::airs::tx_body_merkle::{
        build_instance_layout, build_tx_body_merkle_trace_with_boundary_pins, InstanceRole,
        N_ROUNDS, TXBODY_MERKLE_LAYOUT,
    };
    use crate::composition::tx_validity_hauth::{native_address, native_auth_tag};
    use crate::composition::tx_validity_leaf::native_output_leaf_hash;

    pub fn empty_tx_body() -> TxBody {
        TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    pub fn honest_pins_and_inputs() -> (
        TxBodyMerkleBoundaryPins,
        Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
    ) {
        let inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
            Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);
        let placeholder = TxBodyMerkleBoundaryPins::default();
        let merkle_cols =
            build_tx_body_merkle_trace_with_boundary_pins(&inputs, &placeholder);

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

    pub fn mk_combiner_preimage(seed: u8) -> FriStateCombinerPreimage {
        let mut r_val = [0u8; 32];
        let mut r_hi = [0u8; 32];
        let mut r_lo = [0u8; 32];
        for i in 0..32 {
            r_val[i] = seed ^ (i as u8);
            r_hi[i] = seed.wrapping_add(0x11) ^ (i as u8).wrapping_mul(3);
            r_lo[i] = seed.wrapping_add(0x22) ^ (i as u8).wrapping_mul(5);
        }
        FriStateCombinerPreimage {
            log_slots: 24,
            r_val,
            r_owner_hi: r_hi,
            r_owner_lo: r_lo,
        }
    }

    pub fn mk_secret(seed: u128) -> [Block128; 2] {
        [
            Block128::from(seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(seed.wrapping_mul(0xBF58476D1CE4E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    pub fn mk_output_fields(seed: u128) -> [Block128; 4] {
        let s = seed.wrapping_mul(0xD6E8FEB86659FD93);
        [
            Block128::from(s ^ 0x1111_1111_1111_1111),
            Block128::from(s.wrapping_add(1) ^ 0x2222_2222_2222_2222),
            Block128::from(s.wrapping_add(2) ^ 0x3333_3333_3333_3333),
            Block128::from(s.wrapping_add(3) ^ 0x4444_4444_4444_4444),
        ]
    }

    pub fn mk_eval_point() -> [Block128; 4] {
        let mut r = [Block128::ZERO; 4];
        for (i, slot) in r.iter_mut().enumerate() {
            *slot = Block128::from(0x100u128 + (i as u128) * 0x11);
        }
        r
    }

    pub fn mk_gamma() -> Block128 {
        Block128::from(0xB16B_00B5_0000_BEEFu128)
    }

    pub fn spend_with_owner(seed: u128, slot: u32, owner: [Block128; 2]) -> FriStateOpenClaim {
        let v = Block128::from(seed);
        FriStateOpenClaim {
            slot_index: slot,
            value: v,
            owner_hi: owner[0],
            owner_lo: owner[1],
            delta_value: v,
            delta_owner_hi: owner[0],
            delta_owner_lo: owner[1],
            is_spend: true,
            is_mint: false,
        }
    }

    pub fn empty_with_owner(owner: [Block128; 2]) -> FriStateOpenClaim {
        FriStateOpenClaim {
            slot_index: 0,
            value: Block128::ZERO,
            owner_hi: owner[0],
            owner_lo: owner[1],
            delta_value: Block128::ZERO,
            delta_owner_hi: Block128::ZERO,
            delta_owner_lo: Block128::ZERO,
            is_spend: false,
            is_mint: false,
        }
    }

    pub fn build_honest() -> TxValidityCompositeWithSpine {
        let (pins, merkle_inputs) = honest_pins_and_inputs();

        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner = FriStateCombinerComposite::new(
            prev_preimage,
            prev_fields,
            new_preimage,
            new_fields,
        );

        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            mk_secret(11),
            mk_secret(22),
            mk_secret(33),
            mk_secret(44),
        ];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];

        let tx_body_hash: [Block128; 2] = [pins.tx_body_hash[0], pins.tx_body_hash[1]];

        let auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_auth_tag(secrets[0], tx_body_hash),
            native_auth_tag(secrets[1], tx_body_hash),
            native_auth_tag(secrets[2], tx_body_hash),
            native_auth_tag(secrets[3], tx_body_hash),
        ];

        let mut output_fields: [[Block128; 4]; N_OUTPUTS] = [[Block128::ZERO; 4]; N_OUTPUTS];
        let mut output_leaf_hashes: [[Block128; 2]; N_OUTPUTS] =
            [[Block128::ZERO; 2]; N_OUTPUTS];
        for j in 0..N_OUTPUTS {
            output_fields[j] = mk_output_fields(0x100u128 + j as u128);
            output_leaf_hashes[j] = native_output_leaf_hash(output_fields[j]);
        }

        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            spend_with_owner(11, 0, addrs[0]),
            spend_with_owner(22, 3, addrs[1]),
            empty_with_owner(addrs[2]),
            empty_with_owner(addrs[3]),
        ];
        let base = FriStateOpenWitness::from_claims(claims)
            .with_eval_point(mk_eval_point())
            .with_gamma(mk_gamma());
        let prev_lane_openings = [
            Block128::from(0xA5A5_1234_5678_9ABC_u128),
            Block128::from(0xDEAD_BEEF_CAFE_F00D_u128),
            Block128::from(0x1357_9BDF_2468_ACE0_u128),
        ];
        let new_lane_openings = base.expected_new_lane_openings(prev_lane_openings);
        let open_witness = base.with_lane_openings(prev_lane_openings, new_lane_openings);
        let open_air = FriStateOpenAir::new(
            &claims,
            open_witness.prev_lane_openings,
            open_witness.new_lane_openings,
            mk_eval_point(),
            mk_gamma(),
            open_witness.expected_batched_claims(),
        );

        TxValidityCompositeWithSpine::new(
            pins,
            empty_tx_body(),
            [0u64; 4],
            [0u64; 8],
            0,
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
            output_fields,
            output_leaf_hashes,
        )
    }

    // D.1 — TxBody → boundary pins lowering.
    use noid_poseidon2b::primitives::{fee_leaf as native_fee_leaf, Address};
    use noid_tx::{
        MAX_INPUTS as TX_MAX_INPUTS, MAX_OUTPUTS as TX_MAX_OUTPUTS, TxInput, TxOutput,
    };

    pub fn digest_to_block128_pair(bytes: &[u8; 32]) -> [Block128; 2] {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&bytes[..16]);
        hi.copy_from_slice(&bytes[16..]);
        [
            Block128::from(u128::from_le_bytes(lo)),
            Block128::from(u128::from_le_bytes(hi)),
        ]
    }

    pub fn block128_pair_to_digest(fields: [Block128; 2]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&fields[0].to_u128().to_le_bytes());
        out[16..].copy_from_slice(&fields[1].to_u128().to_le_bytes());
        out
    }

    fn fill_absorb_pins_from_body(pins: &mut TxBodyMerkleBoundaryPins, body: &TxBody) {
        pins.prev_state_root = digest_to_block128_pair(&body.prev_state_root);
        pins.fee_leaf = digest_to_block128_pair(&native_fee_leaf(body.fee));
        for i in 0..TX_MAX_INPUTS {
            let input = body.inputs.get(i).copied().unwrap_or_else(TxInput::dummy);
            let [owner_hi, owner_lo] = input.owner.as_fields();
            pins.input_leaf_absorb[i] = [
                Block128::from(input.slot_index as u128),
                Block128::from(input.value as u128),
                owner_hi,
                owner_lo,
            ];
        }
        for j in 0..TX_MAX_OUTPUTS {
            let out = body.outputs.get(j).copied().unwrap_or_else(TxOutput::dummy);
            let [owner_hi, owner_lo] = out.owner.as_fields();
            pins.output_leaf_absorb[j] = [
                Block128::from(out.value as u128),
                owner_hi,
                owner_lo,
            ];
        }
    }

    /// Derive `(pins, merkle_inputs)` from a realistic TxBody. Leaf
    /// rate lanes get overridden from pins inside the Merkle AIR, so
    /// `merkle_inputs` stays all-zero.
    pub fn lower_tx_body_to_pins(
        body: &TxBody,
    ) -> (
        TxBodyMerkleBoundaryPins,
        Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
    ) {
        let merkle_inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
            Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);
        let mut placeholder = TxBodyMerkleBoundaryPins::default();
        fill_absorb_pins_from_body(&mut placeholder, body);
        placeholder.tx_body_hash = [Block128::ZERO; 2];
        let merkle_cols =
            build_tx_body_merkle_trace_with_boundary_pins(&merkle_inputs, &placeholder);
        let layout = build_instance_layout();
        let wrap_meta = layout
            .iter()
            .find(|m| matches!(m.role, InstanceRole::WrapPerm))
            .expect("wrap instance present");
        let wrap_out_row = wrap_meta.slot_base_row + N_ROUNDS;
        let s0 = merkle_cols[TXBODY_MERKLE_LAYOUT.s][wrap_out_row];
        let s1 = merkle_cols[TXBODY_MERKLE_LAYOUT.s + 1][wrap_out_row];
        let mut pins = placeholder;
        pins.tx_body_hash = [s0, s1];
        (pins, merkle_inputs)
    }

    pub fn address_from_fields(fields: [Block128; 2]) -> Address {
        Address(block128_pair_to_digest(fields))
    }

    /// Stage 5.7 (b) realistic non-empty TxBody honest composite.
    /// 2 live inputs (slots 0,3; values 100,50), 4 live outputs
    /// (40,30,20,10), fee 50. Balance: 150 == 100 + 50.
    pub fn build_honest_realistic() -> TxValidityCompositeWithSpine {
        use noid_poseidon2b::primitives::{AuthTag, SpendSecret};

        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            mk_secret(0xA1),
            mk_secret(0xB2),
            mk_secret(0xC3),
            mk_secret(0xD4),
        ];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];

        let live_values: [u64; 2] = [100, 50];
        let live_slots: [u32; 2] = [0, 3];
        let fee: u64 = 50;
        let out_values: [u64; 4] = [40, 30, 20, 10];

        let out_secrets: [[Block128; 2]; 4] =
            [secrets[0], secrets[1], mk_secret(0x1E), mk_secret(0x2F)];
        let out_owners: [[Block128; 2]; 4] = [
            native_address(out_secrets[0]),
            native_address(out_secrets[1]),
            native_address(out_secrets[2]),
            native_address(out_secrets[3]),
        ];

        let inputs: Vec<TxInput> = (0..FRI_STATE_OPEN_N_INPUTS)
            .map(|i| {
                if i < 2 {
                    TxInput {
                        slot_index: live_slots[i],
                        value: live_values[i],
                        owner: address_from_fields(addrs[i]),
                        spend_secret: SpendSecret(block128_pair_to_digest(secrets[i])),
                        auth_tag: AuthTag([0u8; 32]),
                        valid: true,
                    }
                } else {
                    TxInput::dummy()
                }
            })
            .collect();
        let outputs: Vec<TxOutput> = (0..N_OUTPUTS)
            .map(|j| {
                if j < 4 {
                    TxOutput {
                        value: out_values[j],
                        owner: address_from_fields(out_owners[j]),
                        valid: true,
                    }
                } else {
                    TxOutput::dummy()
                }
            })
            .collect();

        let mut body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: fee as u128,
            inputs,
            outputs,
        };

        let (pins, merkle_inputs) = lower_tx_body_to_pins(&body);
        let tx_body_hash = pins.tx_body_hash;

        let auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_auth_tag(secrets[0], tx_body_hash),
            native_auth_tag(secrets[1], tx_body_hash),
            native_auth_tag(secrets[2], tx_body_hash),
            native_auth_tag(secrets[3], tx_body_hash),
        ];
        for i in 0..2 {
            body.inputs[i].auth_tag = AuthTag(block128_pair_to_digest(auth_tags[i]));
        }

        let mut output_fields: [[Block128; 4]; N_OUTPUTS] = [[Block128::ZERO; 4]; N_OUTPUTS];
        let mut output_leaf_hashes: [[Block128; 2]; N_OUTPUTS] =
            [[Block128::ZERO; 2]; N_OUTPUTS];
        for j in 0..N_OUTPUTS {
            output_fields[j] = mk_output_fields(0x300u128 + j as u128);
            output_leaf_hashes[j] = native_output_leaf_hash(output_fields[j]);
        }

        let prev_preimage = mk_combiner_preimage(0x7E);
        let new_preimage = mk_combiner_preimage(0xE7);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner = FriStateCombinerComposite::new(
            prev_preimage,
            prev_fields,
            new_preimage,
            new_fields,
        );

        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            spend_with_owner(live_values[0] as u128, live_slots[0], addrs[0]),
            spend_with_owner(live_values[1] as u128, live_slots[1], addrs[1]),
            empty_with_owner(addrs[2]),
            empty_with_owner(addrs[3]),
        ];
        let base = FriStateOpenWitness::from_claims(claims)
            .with_eval_point(mk_eval_point())
            .with_gamma(mk_gamma());
        let prev_lane_openings = [
            Block128::from(0x3333_5555_7777_9999_u128),
            Block128::from(0xAAAA_CCCC_EEEE_1111_u128),
            Block128::from(0x2222_4444_6666_8888_u128),
        ];
        let new_lane_openings = base.expected_new_lane_openings(prev_lane_openings);
        let open_witness = base.with_lane_openings(prev_lane_openings, new_lane_openings);
        let open_air = FriStateOpenAir::new(
            &claims,
            open_witness.prev_lane_openings,
            open_witness.new_lane_openings,
            mk_eval_point(),
            mk_gamma(),
            open_witness.expected_batched_claims(),
        );

        let balance_inputs: [u64; 4] = [live_values[0], live_values[1], 0, 0];
        let mut balance_outputs: [u64; 8] = [0; 8];
        for j in 0..4 {
            balance_outputs[j] = out_values[j];
        }

        TxValidityCompositeWithSpine::new(
            pins,
            body,
            balance_inputs,
            balance_outputs,
            fee,
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
            output_fields,
            output_leaf_hashes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::fixture::{
        build_honest, build_honest_realistic, empty_tx_body, honest_pins_and_inputs,
        mk_combiner_preimage, mk_eval_point, mk_gamma, mk_output_fields, mk_secret,
        spend_with_owner,
    };
    use crate::airs::fri_state_combiner::{
        build_combiner_side_trace, extract_combiner_digest_fields, COMBINER_PERM_LAYOUT,
    };
    use crate::airs::fri_state_open::FriStateOpenClaim;
    use crate::composition::tx_validity_hauth::{native_address, native_auth_tag};
    use crate::composition::tx_validity_leaf::native_output_leaf_hash;

    fn build_honest_all_active() -> TxValidityCompositeWithSpine {
        // 4-active-spend / 8-output honest composite. Exercises every
        // per-input T1/T2a/T2b bridge with a live `FriStateOpenClaim`
        // (no `empty_with_owner` slots). TxBody stays empty — the
        // spine TxValidity 3b-4 sub-block is inactive; the leaf band
        // alone exercises the 4-in / 8-out honest flow end-to-end.
        let (pins, merkle_inputs) = honest_pins_and_inputs();

        let prev_preimage = mk_combiner_preimage(0x3C);
        let new_preimage = mk_combiner_preimage(0xC3);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner = FriStateCombinerComposite::new(
            prev_preimage,
            prev_fields,
            new_preimage,
            new_fields,
        );

        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            mk_secret(101),
            mk_secret(202),
            mk_secret(303),
            mk_secret(404),
        ];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];

        let tx_body_hash: [Block128; 2] = [pins.tx_body_hash[0], pins.tx_body_hash[1]];

        let auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_auth_tag(secrets[0], tx_body_hash),
            native_auth_tag(secrets[1], tx_body_hash),
            native_auth_tag(secrets[2], tx_body_hash),
            native_auth_tag(secrets[3], tx_body_hash),
        ];

        let mut output_fields: [[Block128; 4]; N_OUTPUTS] = [[Block128::ZERO; 4]; N_OUTPUTS];
        let mut output_leaf_hashes: [[Block128; 2]; N_OUTPUTS] =
            [[Block128::ZERO; 2]; N_OUTPUTS];
        for j in 0..N_OUTPUTS {
            output_fields[j] = mk_output_fields(0x200u128 + j as u128);
            output_leaf_hashes[j] = native_output_leaf_hash(output_fields[j]);
        }

        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            spend_with_owner(101, 0, addrs[0]),
            spend_with_owner(202, 3, addrs[1]),
            spend_with_owner(303, 5, addrs[2]),
            spend_with_owner(404, 7, addrs[3]),
        ];
        let base = FriStateOpenWitness::from_claims(claims)
            .with_eval_point(mk_eval_point())
            .with_gamma(mk_gamma());
        let prev_lane_openings = [
            Block128::from(0xA5A5_1234_5678_9ABC_u128),
            Block128::from(0xDEAD_BEEF_CAFE_F00D_u128),
            Block128::from(0x1357_9BDF_2468_ACE0_u128),
        ];
        let new_lane_openings = base.expected_new_lane_openings(prev_lane_openings);
        let open_witness = base.with_lane_openings(prev_lane_openings, new_lane_openings);
        let open_air = FriStateOpenAir::new(
            &claims,
            open_witness.prev_lane_openings,
            open_witness.new_lane_openings,
            mk_eval_point(),
            mk_gamma(),
            open_witness.expected_batched_claims(),
        );

        TxValidityCompositeWithSpine::new(
            pins,
            empty_tx_body(),
            [0u64; 4],
            [0u64; 8],
            0,
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
            output_fields,
            output_leaf_hashes,
        )
    }

    #[test]
    fn honest_trace_accepts_all_active_inputs() {
        let comp = build_honest_all_active();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    /// Stage 5.7 (b) — realistic non-empty TxBody honest trace.
    #[test]
    fn honest_trace_accepts_realistic_tx_body() {
        let comp = build_honest_realistic();
        let trace = comp.build_trace();
        assert!(
            comp.air().check(&trace),
            "realistic non-empty TxBody honest trace must accept",
        );
    }

    /// D.2a — tampering a live `TxInput.auth_tag` off its native MAC
    /// must be caught by the restore-loop's `debug_assert_eq!`.
    #[test]
    #[should_panic(expected = "input 0: spine-written AuthTagHi must equal native MAC")]
    fn d2a_restore_guard_detects_live_auth_tag_mismatch() {
        use noid_poseidon2b::primitives::AuthTag;
        let mut comp = build_honest_realistic();
        let mut bad = comp.body.inputs[0].auth_tag.0;
        bad[0] ^= 0xFF;
        comp.body.inputs[0].auth_tag = AuthTag(bad);
        let _ = comp.build_trace();
    }

    #[test]
    fn layout_constants_agree() {
        assert_eq!(LEAF_BAND_RESERVED, TX_VALIDITY_LEAF_N_COLS);
        assert_eq!(SPINE_BLOCK_OUTER_BASE, LEAF_BAND_RESERVED);
        assert_eq!(
            tx_validity_with_spine_n_cols(),
            LEAF_BAND_RESERVED + spine_n_cols()
        );
        assert_eq!(TX_VALIDITY_WITH_SPINE_LOG_ROWS, SPINE_LOG_ROWS);
        assert_eq!(TX_VALIDITY_WITH_SPINE_LOG_ROWS, TX_VALIDITY_LEAF_LOG_ROWS);
    }

    #[test]
    fn spine_layout_resolves_inside_outer() {
        let comp = build_honest();
        let layout = comp.spine_layout();
        assert_eq!(layout.block_base(), SPINE_BLOCK_OUTER_BASE);
        assert_eq!(layout.block_end(), tx_validity_with_spine_n_cols());
        for input in 0..4 {
            let hi = layout.auth_tag_hi_outer_cell(input);
            let lo = layout.auth_tag_lo_outer_cell(input);
            assert!(hi.col >= layout.block_base() && hi.col < layout.block_end());
            assert!(lo.col >= layout.block_base() && lo.col < layout.block_end());
        }
        for output in 0..8 {
            for lane in 0..2 {
                let cell = layout.output_leaf_a_outer_cell(output, lane);
                assert!(cell.col >= layout.block_base() && cell.col < layout.block_end());
            }
        }
        for lane in 0..2 {
            let cell = layout.wrap_output_outer_cell(lane);
            assert!(cell.col >= layout.block_base() && cell.col < layout.block_end());
        }
    }

    #[test]
    fn honest_trace_accepts() {
        let comp = build_honest();
        let trace = comp.build_trace();
        assert_eq!(trace.columns.len(), tx_validity_with_spine_n_cols());
        assert_eq!(
            trace.columns[0].len(),
            1usize << TX_VALIDITY_WITH_SPINE_LOG_ROWS
        );
        assert!(comp.air().check(&trace));
    }

    #[test]
    fn spine_wrap_output_tamper_rejects() {
        let comp = build_honest();
        let mut trace = comp.build_trace();
        let wrap = comp.spine_layout().wrap_output_outer_cell(0);
        trace.columns[wrap.col][wrap.row] =
            trace.columns[wrap.col][wrap.row] + Block128::ONE;
        assert!(!comp.air().check(&trace));
    }

    #[test]
    fn spine_txv_live_mask_tamper_rejects() {
        let comp = build_honest();
        let mut trace = comp.build_trace();
        let mask_col = comp.spine_layout().txv_live_mask_outer_col();
        trace.columns[mask_col][0] = trace.columns[mask_col][0] + Block128::ONE;
        assert!(!comp.air().check(&trace));
    }

    #[test]
    fn t2a_retarget_dst_hi_tamper_rejects_per_input() {
        // PR B.6: per-input T2a-hi dst is now the spine's
        // `auth_tag_hi_outer_cell(i)` (= `TxValidityCol::AuthTagHi`
        // at row i). Tampering it after `build_trace`'s final pass
        // breaks the HAuth bridge tie (`spine cell == HAuth squeeze
        // == native_auth_tag(secrets[i], tx_body_hash)`).
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let comp = build_honest();
            let mut trace = comp.build_trace();
            let cell = comp.spine_layout().auth_tag_hi_outer_cell(i);
            trace.columns[cell.col][cell.row] =
                trace.columns[cell.col][cell.row] + Block128::ONE;
            assert!(
                !comp.air().check(&trace),
                "T2a-hi tamper at input {i} should reject"
            );
        }
    }

    #[test]
    fn t2a_retarget_dst_lo_tamper_rejects_per_input() {
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let comp = build_honest();
            let mut trace = comp.build_trace();
            let cell = comp.spine_layout().auth_tag_lo_outer_cell(i);
            trace.columns[cell.col][cell.row] =
                trace.columns[cell.col][cell.row] + Block128::ONE;
            assert!(
                !comp.air().check(&trace),
                "T2a-lo tamper at input {i} should reject"
            );
        }
    }

    #[test]
    fn t2a_retarget_cells_carry_native_auth_tags() {
        // Sanity: after honest `build_trace`, each spine T2a dst
        // carries `native_auth_tag(secrets[i], tx_body_hash)`. This
        // is the value the bridge ties HAuth squeeze to.
        let comp = build_honest();
        let trace = comp.build_trace();
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let expected = native_auth_tag(comp.secrets[i], comp.tx_body_hash);
            let hi = comp.spine_layout().auth_tag_hi_outer_cell(i);
            let lo = comp.spine_layout().auth_tag_lo_outer_cell(i);
            assert_eq!(trace.columns[hi.col][hi.row], expected[0], "input {i} hi");
            assert_eq!(trace.columns[lo.col][lo.row], expected[1], "input {i} lo");
        }
    }

    #[test]
    fn leaf_band_t2a_pi_pin_columns_are_no_longer_emitted() {
        // PR B.6: with T2a retarget the leaf composite no longer
        // emits `PublicColumn::pinned_row_programme` programmes for
        // T2a dsts at the old leaf-band cols. Verify the legacy-dst
        // column is NOT a declared public column.
        use crate::composition::tx_validity_hauth::auth_tag_dst_cols;
        let comp = build_honest();
        let publics = comp.air().public_columns();
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let (hi_col, lo_col) = auth_tag_dst_cols(i);
            assert!(
                publics.iter().all(|pc| pc.col != hi_col),
                "T2a hi dst col {hi_col} (input {i}) must not be a PublicColumn after retarget"
            );
            assert!(
                publics.iter().all(|pc| pc.col != lo_col),
                "T2a lo dst col {lo_col} (input {i}) must not be a PublicColumn after retarget"
            );
        }
    }

    #[test]
    fn t3_retarget_dst_hi_tamper_rejects_per_output() {
        // PR B.5: per-output T3 dst lives at the spine's
        // `output_leaf_a_outer_cell(j, 0)`. Tampering it after
        // `build_trace`'s final pass breaks the HLeaf bridge tie
        // (`spine cell == HLeaf squeeze == native_output_leaf_hash`).
        for j in 0..N_OUTPUTS {
            let comp = build_honest();
            let mut trace = comp.build_trace();
            let cell = comp.spine_layout().output_leaf_a_outer_cell(j, 0);
            trace.columns[cell.col][cell.row] =
                trace.columns[cell.col][cell.row] + Block128::ONE;
            assert!(
                !comp.air().check(&trace),
                "T3-hi tamper at output {j} should reject"
            );
        }
    }

    #[test]
    fn t3_retarget_dst_lo_tamper_rejects_per_output() {
        for j in 0..N_OUTPUTS {
            let comp = build_honest();
            let mut trace = comp.build_trace();
            let cell = comp.spine_layout().output_leaf_a_outer_cell(j, 1);
            trace.columns[cell.col][cell.row] =
                trace.columns[cell.col][cell.row] + Block128::ONE;
            assert!(
                !comp.air().check(&trace),
                "T3-lo tamper at output {j} should reject"
            );
        }
    }

    #[test]
    fn t3_retarget_cells_carry_native_leaf_hashes() {
        // Sanity: after honest `build_trace`, each spine T3 dst
        // carries `native_output_leaf_hash(output_fields[j])`. This
        // is the value the bridge ties HLeaf squeeze to.
        let comp = build_honest();
        let trace = comp.build_trace();
        for j in 0..N_OUTPUTS {
            let expected = native_output_leaf_hash(comp.output_fields[j]);
            let hi = comp.spine_layout().output_leaf_a_outer_cell(j, 0);
            let lo = comp.spine_layout().output_leaf_a_outer_cell(j, 1);
            assert_eq!(trace.columns[hi.col][hi.row], expected[0], "output {j} hi");
            assert_eq!(trace.columns[lo.col][lo.row], expected[1], "output {j} lo");
        }
    }

    #[test]
    fn leaf_band_t3_pi_pin_columns_are_no_longer_emitted() {
        // PR B.5: with T3 retarget the leaf composite no longer
        // emits `PublicColumn::pinned_row_programme` programmes for
        // T3 dsts. Verify by checking that the legacy-dst column is
        // NOT a declared public column of the composite air.
        use crate::composition::tx_validity_leaf::{
            leaf_hash_dst_cols,
        };
        let comp = build_honest();
        let publics = comp.air().public_columns();
        for j in 0..N_OUTPUTS {
            let (hi_col, lo_col) = leaf_hash_dst_cols(j);
            assert!(
                publics.iter().all(|pc| pc.col != hi_col),
                "T3 hi dst col {hi_col} (output {j}) must not be a PublicColumn after retarget"
            );
            assert!(
                publics.iter().all(|pc| pc.col != lo_col),
                "T3 lo dst col {lo_col} (output {j}) must not be a PublicColumn after retarget"
            );
        }
    }

    #[test]
    fn t1_retarget_owner_hi_tamper_rejects_per_input() {
        // T1 ties HAddr squeeze → FriStateOpen owner columns in the
        // leaf band. Row `i` of `SKEL_OPEN_COL_OFFSET + COL_OWNER_HI`
        // is the per-input T1-hi dst; tampering breaks the HAddr
        // bridge.
        use crate::airs::fri_state_open::COL_OWNER_HI;
        use crate::composition::tx_validity_composite::SKEL_OPEN_COL_OFFSET;
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let comp = build_honest();
            let mut trace = comp.build_trace();
            let col = SKEL_OPEN_COL_OFFSET + COL_OWNER_HI;
            trace.columns[col][i] = trace.columns[col][i] + Block128::ONE;
            assert!(
                !comp.air().check(&trace),
                "T1-hi tamper at input {i} should reject"
            );
        }
    }

    #[test]
    fn t1_retarget_owner_lo_tamper_rejects_per_input() {
        use crate::airs::fri_state_open::COL_OWNER_LO;
        use crate::composition::tx_validity_composite::SKEL_OPEN_COL_OFFSET;
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let comp = build_honest();
            let mut trace = comp.build_trace();
            let col = SKEL_OPEN_COL_OFFSET + COL_OWNER_LO;
            trace.columns[col][i] = trace.columns[col][i] + Block128::ONE;
            assert!(
                !comp.air().check(&trace),
                "T1-lo tamper at input {i} should reject"
            );
        }
    }

    #[test]
    fn t2b_leaf_band_dst_hi_tamper_rejects_per_input() {
        // T2b stays on the leaf band's per-input unpinned dst cells
        // (5.6 default path). Tampering `pre_s_b` hi at its leaf-band
        // row breaks HAuth's pre-S_B bridge tie.
        use crate::composition::tx_validity_hauth::{
            pre_s_b_dst_cols, pre_s_b_hi_dst_row,
        };
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let comp = build_honest();
            let mut trace = comp.build_trace();
            let (hi_col, _) = pre_s_b_dst_cols(i);
            let row = pre_s_b_hi_dst_row(i);
            trace.columns[hi_col][row] =
                trace.columns[hi_col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&trace),
                "T2b-hi tamper at input {i} should reject"
            );
        }
    }

    #[test]
    fn t2b_leaf_band_dst_lo_tamper_rejects_per_input() {
        use crate::composition::tx_validity_hauth::{
            pre_s_b_dst_cols, pre_s_b_lo_dst_row,
        };
        for i in 0..FRI_STATE_OPEN_N_INPUTS {
            let comp = build_honest();
            let mut trace = comp.build_trace();
            let (_, lo_col) = pre_s_b_dst_cols(i);
            let row = pre_s_b_lo_dst_row(i);
            trace.columns[lo_col][row] =
                trace.columns[lo_col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&trace),
                "T2b-lo tamper at input {i} should reject"
            );
        }
    }

    #[test]
    fn leaf_band_combiner_tamper_rejects() {
        use crate::composition::tx_validity_composite::SKEL_COMBINER_COL_OFFSET;
        let comp = build_honest();
        let mut trace = comp.build_trace();
        // Tamper a combiner sub-AIR column inside the combiner window
        // (rows < 2^9 = 512). The row-window wrapper masks combiner
        // constraints off past row 511 but they remain active inside.
        trace.columns[SKEL_COMBINER_COL_OFFSET][1] =
            trace.columns[SKEL_COMBINER_COL_OFFSET][1] + Block128::ONE;
        assert!(!comp.air().check(&trace));
    }
}
