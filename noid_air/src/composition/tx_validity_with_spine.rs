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
    write_leaf_block_traces, TxValidityCompositeLeaf, N_OUTPUTS, TX_VALIDITY_LEAF_LOG_ROWS,
    TX_VALIDITY_LEAF_N_COLS,
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
    body: TxBody,
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

        // Build the leaf composite and consume it for its constraints /
        // publics + witness pieces required to rebuild the leaf-band
        // sub-trace.
        let leaf = TxValidityCompositeLeaf::new(
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
            output_fields,
            output_leaf_hashes,
        );
        let (
            leaf_air,
            combiner,
            open_witness,
            open_public_columns,
            secrets,
            tx_body_hash,
            _auth_tags,
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

        // Leaf-band.
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

#[cfg(test)]
mod tests {
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

    fn empty_tx_body() -> TxBody {
        TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    fn honest_pins_and_inputs() -> (
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

    fn mk_combiner_preimage(seed: u8) -> FriStateCombinerPreimage {
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

    fn mk_secret(seed: u128) -> [Block128; 2] {
        [
            Block128::from(seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(seed.wrapping_mul(0xBF58476D1CE4E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    fn mk_output_fields(seed: u128) -> [Block128; 4] {
        let s = seed.wrapping_mul(0xD6E8FEB86659FD93);
        [
            Block128::from(s ^ 0x1111_1111_1111_1111),
            Block128::from(s.wrapping_add(1) ^ 0x2222_2222_2222_2222),
            Block128::from(s.wrapping_add(2) ^ 0x3333_3333_3333_3333),
            Block128::from(s.wrapping_add(3) ^ 0x4444_4444_4444_4444),
        ]
    }

    fn mk_eval_point() -> [Block128; 4] {
        let mut r = [Block128::ZERO; 4];
        for (i, slot) in r.iter_mut().enumerate() {
            *slot = Block128::from(0x100u128 + (i as u128) * 0x11);
        }
        r
    }

    fn mk_gamma() -> Block128 {
        Block128::from(0xB16B_00B5_0000_BEEFu128)
    }

    fn spend_with_owner(seed: u128, slot: u32, owner: [Block128; 2]) -> FriStateOpenClaim {
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

    fn empty_with_owner(owner: [Block128; 2]) -> FriStateOpenClaim {
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

    fn build_honest() -> TxValidityCompositeWithSpine {
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
    fn leaf_band_t2a_dst_tamper_rejects() {
        // The per-input T2a-hi destination column is a `PublicColumn`
        // pinned to the declared auth tag at the dst row. Mutating
        // that programmed cell after `build_trace`'s final overwrite
        // pass breaks the public-column check and rejects.
        use crate::composition::tx_validity_hauth::auth_tag_dst_cols;
        let comp = build_honest();
        let mut trace = comp.build_trace();
        let (hi_col, _lo_col) = auth_tag_dst_cols(0);
        // Pinned row for input 0's auth_tag_hi (mirrors the leaf
        // composite's `auth_tag_hi_dst_row(0) = HAUTH_N_ROWS + 2`).
        let row = crate::airs::hauth::HAUTH_N_ROWS + 2;
        trace.columns[hi_col][row] = trace.columns[hi_col][row] + Block128::ONE;
        assert!(!comp.air().check(&trace));
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
