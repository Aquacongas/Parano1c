// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.4 — [`TxValidityCompositeFull`].
//!
//! OP-1.δ.1 — replaced the legacy per-input `emit_haddr_block` loop
//! (4 × `HAddrAir` at `HADDR_LOG_ROWS`) with a single
//! [`emit_shared_haddr_block`] call that packs N independent
//! `derive_address` sponges into one [`HAddrMultiAir`] at
//! `inner_log_rows = haddr_multi_min_log_rows(N_INPUTS)`. Column
//! savings for N_INPUTS = 4: `4 · (HADDR_N_COLS + 9) = 320 outer cols`
//! → `haddr_multi_n_cols(4) + 1 + 8·4 = 113 outer cols`.
//!
//! Soundness: each input `i`'s squeeze cell
//! `(s_B[0], s_B[1]) @ haddr_multi_row_output(i)` is bridged via a
//! T1 lane pair to `FriStateOpen.owner_{hi,lo}[row = i]` — exactly
//! the contract the legacy per-input path enforced (see
//! `haddr_multi.rs::single_instance_output_matches_legacy_haddr`).

use crate::airs::fri_state_combiner::FRI_STATE_COMBINER_LOG_ROWS;
use crate::airs::fri_state_combiner_composite::{
    FriStateCombinerComposite, COMBINER_COMPOSITE_LOG_ROWS, COMBINER_COMPOSITE_N_COLS,
};
use crate::airs::fri_state_open::{
    FriStateOpenAir, FriStateOpenWitness, COL_OWNER_HI, COL_OWNER_LO,
    FRI_STATE_OPEN_LOG_ROWS, FRI_STATE_OPEN_N_INPUTS, FRI_STATE_OPEN_N_ROWS,
    FRI_STATE_OPEN_WITNESS_COLS,
};
use crate::airs::haddr_multi::{
    haddr_multi_min_log_rows, haddr_multi_n_cols, haddr_multi_row_output,
    HADDR_MULTI_LAYOUT_B,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWrapper, WrapPolicy,
};
use crate::composition::shared_haddr_block::{
    emit_shared_haddr_block, write_shared_haddr_block_trace, SharedHAddrBlockParams,
    SharedHAddrInputBudget, SharedHAddrInputTargets,
};
use crate::composition::t1_owner_tie::T1LaneColumnBudget;
use crate::composition::tx_validity_composite::{
    SKEL_COMBINER_COL_OFFSET, SKEL_COMBINER_WINDOW_INDICATOR_COL, SKEL_OPEN_COL_OFFSET,
    SKEL_OPEN_WINDOW_INDICATOR_COL, TX_VALIDITY_SKELETON_LOG_ROWS, TX_VALIDITY_SKELETON_N_COLS,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, CompositeAir, Constraint, Trace};
use noid_core::{Block128, TowerField};

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Outer log-rows: inherited from the 5.3 skeleton (1024 rows after
/// OP-1.δ.0).
pub const TX_VALIDITY_FULL_LOG_ROWS: usize = TX_VALIDITY_SKELETON_LOG_ROWS;

/// Number of columns in the shared `HAddrMultiAir` slab.
pub const SHARED_HADDR_MULTI_N_COLS: usize = haddr_multi_n_cols(FRI_STATE_OPEN_N_INPUTS);

/// Inner log-rows of the shared `HAddrMultiAir`.
pub const SHARED_HADDR_MULTI_LOG_ROWS: usize =
    haddr_multi_min_log_rows(FRI_STATE_OPEN_N_INPUTS);

/// Compile-time height sanity.
const _: () = {
    assert!(SHARED_HADDR_MULTI_LOG_ROWS <= TX_VALIDITY_FULL_LOG_ROWS);
    assert!(FRI_STATE_OPEN_LOG_ROWS <= TX_VALIDITY_FULL_LOG_ROWS);
    assert!(FRI_STATE_COMBINER_LOG_ROWS == COMBINER_COMPOSITE_LOG_ROWS);
};

/// Outer column offset of the shared HAddr slab.
pub const FULL_HADDR_BLOCKS_BASE: usize = TX_VALIDITY_SKELETON_N_COLS;

/// Outer column of the shared-HAddr window indicator.
pub const FULL_HADDR_WINDOW_INDICATOR_COL: usize =
    FULL_HADDR_BLOCKS_BASE + SHARED_HADDR_MULTI_N_COLS;

/// Outer column offset of the per-input T1 bridge slab
/// (8 cols/input: 4 hi + 4 lo).
pub const FULL_HADDR_T1_BASE: usize = FULL_HADDR_WINDOW_INDICATOR_COL + 1;

/// Outer columns consumed by the shared-HAddr block (multi-AIR slab +
/// window indicator + per-input T1 bridges).
pub const SHARED_HADDR_OUTER_COLS: usize =
    SHARED_HADDR_MULTI_N_COLS + 1 + 8 * FRI_STATE_OPEN_N_INPUTS;

/// Total outer column count.
pub const TX_VALIDITY_FULL_N_COLS: usize =
    FULL_HADDR_BLOCKS_BASE + SHARED_HADDR_OUTER_COLS;

/// Outer column of input `i`'s squeezed address hi lane inside the
/// shared HAddr slab. Row = [`full_haddr_squeeze_row`]`(i)`.
pub const fn full_haddr_squeeze_hi_col() -> usize {
    FULL_HADDR_BLOCKS_BASE + HADDR_MULTI_LAYOUT_B.s
}

/// Outer column of input `i`'s squeezed address lo lane.
pub const fn full_haddr_squeeze_lo_col() -> usize {
    FULL_HADDR_BLOCKS_BASE + HADDR_MULTI_LAYOUT_B.s + 1
}

/// Outer row of input `i`'s squeezed address inside the shared HAddr
/// slab (the multi-AIR's per-input output row).
pub fn full_haddr_squeeze_row(input: usize) -> usize {
    haddr_multi_row_output(input)
}

/// Per-input T1 bridge column base `(hi_base, lo_base)`. Each lane
/// owns a 4-col sub-budget (bridge + src/dst/transition indicators).
pub const fn full_haddr_t1_bases(input: usize) -> (usize, usize) {
    let base = FULL_HADDR_T1_BASE + 8 * input;
    (base, base + 4)
}

fn shared_haddr_params(outer_n_cols: usize, outer_log_rows: usize) -> SharedHAddrBlockParams {
    let mut inputs = Vec::with_capacity(FRI_STATE_OPEN_N_INPUTS);
    for i in 0..FRI_STATE_OPEN_N_INPUTS {
        let (hi_base, lo_base) = full_haddr_t1_bases(i);
        inputs.push((
            SharedHAddrInputBudget {
                t1_hi_budget: T1LaneColumnBudget {
                    bridge_col: hi_base,
                    src_indicator_col: hi_base + 1,
                    dst_indicator_col: hi_base + 2,
                    transition_indicator_col: hi_base + 3,
                },
                t1_lo_budget: T1LaneColumnBudget {
                    bridge_col: lo_base,
                    src_indicator_col: lo_base + 1,
                    dst_indicator_col: lo_base + 2,
                    transition_indicator_col: lo_base + 3,
                },
            },
            SharedHAddrInputTargets {
                owner_hi_dst_col: SKEL_OPEN_COL_OFFSET + COL_OWNER_HI,
                owner_hi_dst_row: i,
                owner_lo_dst_col: SKEL_OPEN_COL_OFFSET + COL_OWNER_LO,
                owner_lo_dst_row: i,
            },
        ));
    }
    SharedHAddrBlockParams {
        n_inputs: FRI_STATE_OPEN_N_INPUTS,
        col_offset: FULL_HADDR_BLOCKS_BASE,
        window_indicator_col: FULL_HADDR_WINDOW_INDICATOR_COL,
        row_window_start: 0,
        outer_n_cols,
        outer_log_rows,
        inputs,
    }
}

/// Shared entry-point so `tx_validity_hauth`, `tx_validity_leaf`, etc.
/// don't have to re-derive the shared-HAddr wiring. Callers pass the
/// enclosing composite's outer width + log_rows.
pub fn emit_full_shared_haddr(
    outer_n_cols: usize,
    outer_log_rows: usize,
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    let wiring = emit_shared_haddr_block(shared_haddr_params(outer_n_cols, outer_log_rows));
    (wiring.constraints, wiring.public_columns)
}

/// Honest-trace writer for the shared-HAddr block. Returns the per-
/// input `[addr_hi, addr_lo]` squeeze pairs (same shape as the legacy
/// `write_haddr_block_trace`).
pub fn write_full_shared_haddr_trace(
    cols: &mut [Vec<Block128>],
    outer_n_cols: usize,
    outer_log_rows: usize,
    secrets: &[[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
) -> Vec<[Block128; 2]> {
    let params = shared_haddr_params(outer_n_cols, outer_log_rows);
    write_shared_haddr_block_trace(cols, &params, secrets)
}

// ---------------------------------------------------------------------------
// Full composite
// ---------------------------------------------------------------------------

/// Stage 5.4 full composite: combiner + FriStateOpen + shared HAddr
/// (single `HAddrMultiAir` + N T1 bridge pairs).
pub struct TxValidityCompositeFull {
    pub air: CompositeAir,
    combiner: FriStateCombinerComposite,
    open_witness: FriStateOpenWitness,
    open_public_columns: Vec<PublicColumn>,
    /// Per-input spend secrets (hi, lo). One set per `FriStateOpenClaim`
    /// entry; inactive / mint / dummy inputs still need a placeholder
    /// secret — the shared HAddr sub-AIR runs unconditionally on every
    /// packed input row band.
    secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
}

impl TxValidityCompositeFull {
    /// Build the full composite.
    pub fn new(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    ) -> Self {
        let outer_n_cols = TX_VALIDITY_FULL_N_COLS;
        let outer_log_rows = TX_VALIDITY_FULL_LOG_ROWS;

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // Block A — combiner via RowWindowWrapper(MaskOff).
        let (combiner_constraints, combiner_publics) = clone_combiner_parts(&combiner);
        let combiner_view = InnerAirView {
            inner_n_cols: COMBINER_COMPOSITE_N_COLS,
            inner_log_rows: COMBINER_COMPOSITE_LOG_ROWS,
            constraints: combiner_constraints,
            public_columns: combiner_publics,
            requires_true_cyclic_wrap: false,
        };
        let combiner_params = RowWindowParams {
            col_offset: SKEL_COMBINER_COL_OFFSET,
            outer_n_cols,
            outer_log_rows,
            row_window_start: 0,
            row_window_end: 1usize << COMBINER_COMPOSITE_LOG_ROWS,
            window_indicator_col: SKEL_COMBINER_WINDOW_INDICATOR_COL,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: Vec::new(),
        };
        let combiner_wiring = RowWindowWrapper::wrap(combiner_view, combiner_params);
        constraints.extend(combiner_wiring.constraints);
        public_columns.extend(combiner_wiring.public_columns);

        // Block B — FriStateOpen via RowWindowWrapper.
        let (open_n_cols, open_constraints, open_publics) = open_air.into_parts();
        assert_eq!(open_n_cols, FRI_STATE_OPEN_WITNESS_COLS);
        let inner_view = InnerAirView {
            inner_n_cols: open_n_cols,
            inner_log_rows: FRI_STATE_OPEN_LOG_ROWS,
            constraints: open_constraints,
            public_columns: open_publics.clone(),
            requires_true_cyclic_wrap: false,
        };
        let open_params = RowWindowParams {
            col_offset: SKEL_OPEN_COL_OFFSET,
            outer_n_cols,
            outer_log_rows,
            row_window_start: 0,
            row_window_end: FRI_STATE_OPEN_N_ROWS,
            window_indicator_col: SKEL_OPEN_WINDOW_INDICATOR_COL,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: Vec::new(),
        };
        let open_wiring = RowWindowWrapper::wrap(inner_view, open_params);
        constraints.extend(open_wiring.constraints);
        public_columns.extend(open_wiring.public_columns);

        // Block B.out (E.2.b) — output-side FriStateOpenAir (all-EMPTY).
        let (out_open_air, _) =
            crate::composition::tx_validity_composite::build_empty_output_side();
        let (out_open_wiring, _) =
            crate::composition::tx_validity_composite::emit_output_open_wiring(
                out_open_air,
                outer_n_cols,
                outer_log_rows,
            );
        constraints.extend(out_open_wiring.constraints);
        public_columns.extend(out_open_wiring.public_columns);

        // E.2.b.comp-4: slot-index bridge pins (all-zero for EMPTY).
        public_columns.extend(
            crate::composition::tx_validity_composite::emit_out_open_slot_index_publics(
                &crate::composition::tx_validity_composite::OutputSideSource::Empty,
                1usize << outer_log_rows,
            ),
        );

        // Block C — shared HAddr: one `HAddrMultiAir` + N T1 bridge
        // pairs tying each per-input squeeze cell to the corresponding
        // `FriStateOpen.owner_{hi,lo}[row=i]`.
        let (haddr_constraints, haddr_publics) =
            emit_full_shared_haddr(outer_n_cols, outer_log_rows);
        constraints.extend(haddr_constraints);
        public_columns.extend(haddr_publics);

        let air = CompositeAir::from_parts_with_publics(
            outer_log_rows,
            outer_n_cols,
            constraints,
            public_columns,
        );

        Self {
            air,
            combiner,
            open_witness,
            open_public_columns: open_publics,
            secrets,
        }
    }

    /// Build an honest outer trace.
    pub fn build_trace(&self) -> Trace {
        let outer_n_rows = 1usize << TX_VALIDITY_FULL_LOG_ROWS;
        let mut cols: Vec<Vec<Block128>> = (0..TX_VALIDITY_FULL_N_COLS)
            .map(|_| vec![Block128::ZERO; outer_n_rows])
            .collect();

        // Combiner columns — rows [0, 512); beyond silenced.
        let combiner_inner_n_rows = 1usize << COMBINER_COMPOSITE_LOG_ROWS;
        let combiner_trace = self.combiner.build_trace();
        let combiner_cols = combiner_trace.columns;
        assert_eq!(combiner_cols.len(), COMBINER_COMPOSITE_N_COLS);
        for (i, src) in combiner_cols.into_iter().enumerate() {
            assert_eq!(src.len(), combiner_inner_n_rows);
            let dst = &mut cols[SKEL_COMBINER_COL_OFFSET + i];
            for (r, v) in src.into_iter().enumerate() {
                dst[r] = v;
            }
        }

        // Open columns — rows [0, FRI_STATE_OPEN_N_ROWS).
        let open_inner =
            build_open_inner_cols(&self.open_witness, &self.open_public_columns);
        assert_eq!(open_inner.len(), FRI_STATE_OPEN_WITNESS_COLS);
        for (i, src) in open_inner.into_iter().enumerate() {
            let dst = &mut cols[SKEL_OPEN_COL_OFFSET + i];
            for (r, v) in src.into_iter().enumerate() {
                dst[r] = v;
            }
        }

        // E.2.b: output-side open columns (all-EMPTY honest witness).
        crate::composition::tx_validity_composite::write_empty_output_open_trace(&mut cols);

        // Shared HAddr block: single multi-AIR sub-trace + per-input
        // T1 bridges. The helper plants each squeeze value into the
        // corresponding `FriStateOpen.owner_{hi,lo}[row=i]` dst cell.
        let _ = write_full_shared_haddr_trace(
            &mut cols,
            TX_VALIDITY_FULL_N_COLS,
            TX_VALIDITY_FULL_LOG_ROWS,
            &self.secrets,
        );

        // Final pass: overwrite every public column with its programme.
        for pc in self.air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }

        Trace::new(cols)
    }

    pub fn air(&self) -> &CompositeAir {
        &self.air
    }

    pub fn secrets(&self) -> &[[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] {
        &self.secrets
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn clone_combiner_parts(
    c: &FriStateCombinerComposite,
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    use crate::airs::fri_state_combiner::{
        build_combiner_side_trace, extract_combiner_digest_fields, COMBINER_PERM_LAYOUT,
    };
    let prev = *c.prev_preimage();
    let new = *c.new_preimage();
    let prev_fields =
        extract_combiner_digest_fields(&build_combiner_side_trace(&prev), COMBINER_PERM_LAYOUT);
    let new_fields =
        extract_combiner_digest_fields(&build_combiner_side_trace(&new), COMBINER_PERM_LAYOUT);
    FriStateCombinerComposite::new(prev, prev_fields, new, new_fields).into_parts()
}

fn build_open_inner_cols(
    witness: &FriStateOpenWitness,
    publics: &[PublicColumn],
) -> Vec<Vec<Block128>> {
    let mut cols = witness.build_columns(FRI_STATE_OPEN_WITNESS_COLS);
    for pc in publics {
        cols[pc.col] = pc.values.clone();
    }
    cols
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
    use noid_core::{CanonicalSerialize, TowerField};

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

    fn addr_for_secret(secret: [Block128; 2]) -> [Block128; 2] {
        let cols = crate::airs::haddr::build_haddr_trace(secret);
        crate::airs::haddr::extract_haddr_output(&cols)
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

    fn build_full() -> TxValidityCompositeFull {
        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);
        let prev_trace = build_combiner_side_trace(&prev_preimage);
        let new_trace = build_combiner_side_trace(&new_preimage);
        let prev_fields = extract_combiner_digest_fields(&prev_trace, COMBINER_PERM_LAYOUT);
        let new_fields = extract_combiner_digest_fields(&new_trace, COMBINER_PERM_LAYOUT);
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
            addr_for_secret(secrets[0]),
            addr_for_secret(secrets[1]),
            addr_for_secret(secrets[2]),
            addr_for_secret(secrets[3]),
        ];

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

        TxValidityCompositeFull::new(combiner, open_air, open_witness, secrets)
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

    #[test]
    fn layout_constants_agree() {
        assert_eq!(
            TX_VALIDITY_FULL_N_COLS,
            TX_VALIDITY_SKELETON_N_COLS + SHARED_HADDR_OUTER_COLS
        );
        assert_eq!(TX_VALIDITY_FULL_LOG_ROWS, TX_VALIDITY_SKELETON_LOG_ROWS);
        assert_eq!(
            SHARED_HADDR_OUTER_COLS,
            SHARED_HADDR_MULTI_N_COLS + 1 + 8 * FRI_STATE_OPEN_N_INPUTS
        );
    }

    #[test]
    fn honest_trace_accepts() {
        let comp = build_full();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    #[test]
    fn haddr_squeeze_matches_native_address_per_input() {
        use noid_poseidon2b::primitives::{derive_address, SpendSecret};
        let comp = build_full();
        let cols = comp.build_trace().columns;
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let row = full_haddr_squeeze_row(input);
            let addr_hi = cols[full_haddr_squeeze_hi_col()][row];
            let addr_lo = cols[full_haddr_squeeze_lo_col()][row];

            let sec = comp.secrets()[input];
            let hi_bytes = sec[0].to_bytes();
            let lo_bytes = sec[1].to_bytes();
            let mut sec_bytes = [0u8; 32];
            sec_bytes[..16].copy_from_slice(&hi_bytes[..16]);
            sec_bytes[16..].copy_from_slice(&lo_bytes[..16]);
            let native = derive_address(&SpendSecret(sec_bytes));
            let ah = addr_hi.to_bytes();
            let al = addr_lo.to_bytes();
            let mut out = [0u8; 32];
            out[..16].copy_from_slice(&ah[..16]);
            out[16..].copy_from_slice(&al[..16]);
            assert_eq!(out, native.0, "input {input}");

            assert_eq!(cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][input], addr_hi);
            assert_eq!(cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_LO][input], addr_lo);
        }
    }

    #[test]
    fn open_owner_hi_tamper_rejects_via_t1() {
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] =
            cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn open_owner_lo_tamper_rejects_via_t1() {
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_LO][2] =
            cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_LO][2] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_squeeze_tamper_rejects_via_t1() {
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        // Tamper input 1's squeeze hi cell. The multi-AIR rejects
        // directly; even if it didn't, the T1 bridge catches the
        // src mismatch.
        let row = full_haddr_squeeze_row(1);
        let col = full_haddr_squeeze_hi_col();
        cols[col][row] = cols[col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_interior_tamper_rejects() {
        // Tamper an interior cell of the shared multi-AIR slab. Use
        // any non-boundary row inside input 2's band.
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        let col = FULL_HADDR_BLOCKS_BASE + HADDR_MULTI_LAYOUT_B.s + 2;
        let row = full_haddr_squeeze_row(2).saturating_sub(1).max(1);
        cols[col][row] = cols[col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn combiner_tamper_rejects() {
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        let reg = crate::composition::registry::CombinerCompositeCols::new();
        let row = crate::airs::fri_state_combiner::combiner_digest_row();
        cols[reg.prev_digest_hi][row] = cols[reg.prev_digest_hi][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }
}
