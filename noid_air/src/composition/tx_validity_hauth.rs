// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.5 — [`TxValidityCompositeHAuth`].
//!
//! Extends the 5.4 [`super::tx_validity_full::TxValidityCompositeFull`]
//! with `FRI_STATE_OPEN_N_INPUTS` `HAuthAir` instances, one per tx
//! input. Each HAuth block is embedded via [`super::hauth_block`] and
//! wired through two bridge families:
//!
//! - **T2a** — per-input auth-tag tie. The squeezed
//!   `(tag_hi, tag_lo) = s_C[0..2]@HAUTH_OUTPUT_ROW` is bridged to a
//!   pair of outer destination cells (one pair per input) carrying the
//!   declared auth tag. The destinations are pinned as `PublicColumn`
//!   programmes, so the overall contract is
//!   `HAuth.squeeze[i] == declared_auth_tag[i]` with the bridge
//!   mediating the cross-row equality. Stage 5.7 re-points the
//!   destination at `TxValidityCol::AuthTagHi/Lo @ row i` inside the
//!   embedded `TxBodySpineComposite`; the bridge contract is unchanged.
//!
//! - **T2b** — per-input pre-MDS B-seed anchor. The pair
//!   `(pre_s_B[0], pre_s_B[1])@N_ROUNDS` of each HAuth block is bridged
//!   to a pair of outer destination cells reserved per input. These
//!   cells are unpinned at Stage 5.5 (the tx-body-hash consistency
//!   across inputs is already enforced inside each block because the
//!   B-carry gate bakes `tx_body_hash` into the `ABSORB_B` coefficients
//!   at AIR construction time, and every block receives the same
//!   `tx_body_hash`). The per-input T2b dst cells exist to stage the
//!   wiring for Stage 5.7, which re-points them at `TxBodyMerkleAir`'s
//!   wrap-output columns inside the embedded `TxBodySpineComposite` —
//!   closing the absorb operand against the verifier-visible Merkle
//!   root without changing the bridge contract.
//!
//! # Note on shared vs per-input T2b
//!
//! Sharing one pair of T2b destination cells across all `N_INPUTS`
//! blocks is not viable at this stage: `pre_s_B[lane] = A.s[lane] +
//! tx_body[lane]`, and `A.s` depends on the per-input secret, so the
//! bridged source values differ per block. A shared destination is
//! only consistent once T2b is re-pointed at a cell carrying
//! `tx_body_hash` directly (Stage 5.7 Merkle wrap-output).
//!
//! # Layout (on top of 5.4)
//!
//! All new columns append to the right of the 5.4 composite:
//!
//! ```text
//!   [0, TX_VALIDITY_FULL_N_COLS)         — inherited from 5.4
//!   [FULL_HAUTH_BLOCKS_BASE, +4·HAUTH_BLOCK_OUTER_COLS)  — HAuth blocks
//!   [AUTH_TAG_DSTS…]                                     — per-input T2a dsts
//!   [PRE_S_B_DSTS…]                                      — per-input T2b dsts
//! ```
//!
//! Each HAuth block's 4 lane bridges carry 4 outer cols each (bridge +
//! 3 indicators); the block width is
//! `HAUTH_N_COLS + 1 (window) + 4·4 (bridges) = HAUTH_N_COLS + 17`.
//!
//! Outer log-rows inherits from 5.4 (512 rows). HAuth's 256-row
//! footprint fits. log_rows stays 9 — Stage 5.7 lifts it to 13 once
//! `TxBodySpineComposite` joins.

use crate::airs::fri_state_combiner::FRI_STATE_COMBINER_LOG_ROWS;
use crate::airs::fri_state_combiner_composite::{
    FriStateCombinerComposite, COMBINER_COMPOSITE_LOG_ROWS, COMBINER_COMPOSITE_N_COLS,
};
use crate::airs::fri_state_open::{
    FriStateOpenAir, FriStateOpenWitness, COL_OWNER_HI, COL_OWNER_LO,
    FRI_STATE_OPEN_LOG_ROWS, FRI_STATE_OPEN_N_INPUTS, FRI_STATE_OPEN_N_ROWS,
    FRI_STATE_OPEN_WITNESS_COLS,
};
use crate::airs::haddr::{HADDR_LOG_ROWS, HADDR_N_COLS};
use crate::airs::hauth::{HAUTH_LOG_ROWS, HAUTH_N_COLS};
use crate::composition::haddr_block::{
    emit_haddr_block, write_haddr_block_trace, HAddrBlockColumns, HAddrBlockParams,
    HAddrBlockT1Targets,
};
use crate::composition::hauth_block::{
    emit_hauth_block, write_hauth_block_trace, HAuthBlockColumns, HAuthBlockParams,
    HAuthBlockTargets,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWrapper, WrapPolicy,
};
use crate::composition::t1_owner_tie::{LaneBridgeBudget, T1LaneColumnBudget};
use crate::composition::tx_validity_composite::{
    SKEL_COMBINER_COL_OFFSET, SKEL_OPEN_COL_OFFSET, SKEL_OPEN_WINDOW_INDICATOR_COL,
};
use crate::composition::tx_validity_full::{
    full_haddr_block_base, TX_VALIDITY_FULL_LOG_ROWS, TX_VALIDITY_FULL_N_COLS,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, CompositeAir, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::{Block128, TowerField};

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Outer log-rows: inherited from 5.4.
pub const TX_VALIDITY_HAUTH_LOG_ROWS: usize = TX_VALIDITY_FULL_LOG_ROWS;

/// Compile-time height sanity.
const _: () = {
    assert!(HAUTH_LOG_ROWS <= TX_VALIDITY_HAUTH_LOG_ROWS);
    assert!(HADDR_LOG_ROWS <= TX_VALIDITY_HAUTH_LOG_ROWS);
    assert!(FRI_STATE_OPEN_LOG_ROWS <= TX_VALIDITY_HAUTH_LOG_ROWS);
    assert!(FRI_STATE_COMBINER_LOG_ROWS == COMBINER_COMPOSITE_LOG_ROWS);
};

/// Per-HAuth-block extra outer columns: sub-AIR + window indicator +
/// 4 lane bridges × 4 cols each.
pub const HAUTH_BLOCK_OUTER_COLS: usize = HAUTH_N_COLS + 1 + 16;

/// Outer col offset of the first HAuth block (right after the 5.4
/// column band).
pub const FULL_HAUTH_BLOCKS_BASE: usize = TX_VALIDITY_FULL_N_COLS;

/// Per-input T2a destination column base. Each input reserves two
/// columns (auth_tag_hi, auth_tag_lo). Destinations are pinned via
/// `PublicColumn` programmes carrying the declared auth tag for the
/// corresponding input.
pub const AUTH_TAG_DST_BASE: usize =
    FULL_HAUTH_BLOCKS_BASE + FRI_STATE_OPEN_N_INPUTS * HAUTH_BLOCK_OUTER_COLS;

/// Per-input T2b destination column base. Each input reserves two
/// columns (pre_s_B_hi, pre_s_B_lo). At 5.5 these cells are unpinned
/// — they just receive the honest `pre_s_B[lane]@N_ROUNDS` value and
/// are bridged to the corresponding HAuth block. Stage 5.7 re-points
/// them at `TxBodyMerkleAir`'s wrap-output columns.
pub const PRE_S_B_DST_BASE: usize = AUTH_TAG_DST_BASE + 2 * FRI_STATE_OPEN_N_INPUTS;

/// Total outer column count.
pub const TX_VALIDITY_HAUTH_N_COLS: usize =
    PRE_S_B_DST_BASE + 2 * FRI_STATE_OPEN_N_INPUTS;

/// Per-input HAuth block column base.
pub const fn full_hauth_block_base(input: usize) -> usize {
    FULL_HAUTH_BLOCKS_BASE + input * HAUTH_BLOCK_OUTER_COLS
}

/// Per-input auth-tag dst columns `(hi, lo)`.
pub const fn auth_tag_dst_cols(input: usize) -> (usize, usize) {
    let base = AUTH_TAG_DST_BASE + 2 * input;
    (base, base + 1)
}

/// Per-input pre-MDS B-seed dst columns `(hi, lo)`.
pub const fn pre_s_b_dst_cols(input: usize) -> (usize, usize) {
    let base = PRE_S_B_DST_BASE + 2 * input;
    (base, base + 1)
}

// HAuth block internal sub-layout (relative to its base):
const REL_HAUTH_SUBAIR_COL: usize = 0;
const REL_HAUTH_WINDOW_INDICATOR_COL: usize = HAUTH_N_COLS;
const REL_T2A_HI_BRIDGE: usize = HAUTH_N_COLS + 1;
const REL_T2A_HI_SRC: usize = HAUTH_N_COLS + 2;
const REL_T2A_HI_DST_IND: usize = HAUTH_N_COLS + 3;
const REL_T2A_HI_TRANS: usize = HAUTH_N_COLS + 4;
const REL_T2A_LO_BRIDGE: usize = HAUTH_N_COLS + 5;
const REL_T2A_LO_SRC: usize = HAUTH_N_COLS + 6;
const REL_T2A_LO_DST_IND: usize = HAUTH_N_COLS + 7;
const REL_T2A_LO_TRANS: usize = HAUTH_N_COLS + 8;
const REL_T2B_HI_BRIDGE: usize = HAUTH_N_COLS + 9;
const REL_T2B_HI_SRC: usize = HAUTH_N_COLS + 10;
const REL_T2B_HI_DST_IND: usize = HAUTH_N_COLS + 11;
const REL_T2B_HI_TRANS: usize = HAUTH_N_COLS + 12;
const REL_T2B_LO_BRIDGE: usize = HAUTH_N_COLS + 13;
const REL_T2B_LO_SRC: usize = HAUTH_N_COLS + 14;
const REL_T2B_LO_DST_IND: usize = HAUTH_N_COLS + 15;
const REL_T2B_LO_TRANS: usize = HAUTH_N_COLS + 16;

// Per-input auth-tag dst rows. Each block gets its own row per lane.
const fn auth_tag_hi_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 2 + 8 * input
}
const fn auth_tag_lo_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 4 + 8 * input
}

// Per-input pre-MDS B-seed dst rows. Distinct from the T2a rows so
// bridge intervals on a shared column don't alias. (Currently each
// T2b dst has its own column pair per input; rows still need to
// differ from the src row N_ROUNDS — which they do by construction.)
const fn pre_s_b_hi_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 6 + 8 * input
}
const fn pre_s_b_lo_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 8 + 8 * input
}

fn hauth_block_params_for(
    input: usize,
    outer_n_cols: usize,
    tx_body_hash: [Block128; 2],
) -> HAuthBlockParams {
    let base = full_hauth_block_base(input);
    let (tag_hi_col, tag_lo_col) = auth_tag_dst_cols(input);
    let (pre_hi_col, pre_lo_col) = pre_s_b_dst_cols(input);
    HAuthBlockParams {
        cols: HAuthBlockColumns {
            col_offset: base + REL_HAUTH_SUBAIR_COL,
            window_indicator_col: base + REL_HAUTH_WINDOW_INDICATOR_COL,
            t2a_hi_budget: LaneBridgeBudget {
                bridge_col: base + REL_T2A_HI_BRIDGE,
                src_indicator_col: base + REL_T2A_HI_SRC,
                dst_indicator_col: base + REL_T2A_HI_DST_IND,
                transition_indicator_col: base + REL_T2A_HI_TRANS,
            },
            t2a_lo_budget: LaneBridgeBudget {
                bridge_col: base + REL_T2A_LO_BRIDGE,
                src_indicator_col: base + REL_T2A_LO_SRC,
                dst_indicator_col: base + REL_T2A_LO_DST_IND,
                transition_indicator_col: base + REL_T2A_LO_TRANS,
            },
            t2b_hi_budget: LaneBridgeBudget {
                bridge_col: base + REL_T2B_HI_BRIDGE,
                src_indicator_col: base + REL_T2B_HI_SRC,
                dst_indicator_col: base + REL_T2B_HI_DST_IND,
                transition_indicator_col: base + REL_T2B_HI_TRANS,
            },
            t2b_lo_budget: LaneBridgeBudget {
                bridge_col: base + REL_T2B_LO_BRIDGE,
                src_indicator_col: base + REL_T2B_LO_SRC,
                dst_indicator_col: base + REL_T2B_LO_DST_IND,
                transition_indicator_col: base + REL_T2B_LO_TRANS,
            },
        },
        row_window_start: 0,
        outer_n_cols,
        outer_log_rows: TX_VALIDITY_HAUTH_LOG_ROWS,
        tx_body_hash,
        targets: HAuthBlockTargets {
            auth_tag_hi_dst_col: tag_hi_col,
            auth_tag_hi_dst_row: auth_tag_hi_dst_row(input),
            auth_tag_lo_dst_col: tag_lo_col,
            auth_tag_lo_dst_row: auth_tag_lo_dst_row(input),
            tx_body_hi_dst_col: pre_hi_col,
            tx_body_hi_dst_row: pre_s_b_hi_dst_row(input),
            tx_body_lo_dst_col: pre_lo_col,
            tx_body_lo_dst_row: pre_s_b_lo_dst_row(input),
        },
    }
}

fn haddr_block_params_for(input: usize, outer_n_cols: usize) -> HAddrBlockParams {
    let base = full_haddr_block_base(input);
    const REL_HADDR_SUBAIR_COL: usize = 0;
    const REL_WINDOW_INDICATOR_COL: usize = HADDR_N_COLS;
    const REL_T1_HI_BRIDGE_COL: usize = HADDR_N_COLS + 1;
    const REL_T1_HI_SRC_IND_COL: usize = HADDR_N_COLS + 2;
    const REL_T1_HI_DST_IND_COL: usize = HADDR_N_COLS + 3;
    const REL_T1_HI_TRANS_IND_COL: usize = HADDR_N_COLS + 4;
    const REL_T1_LO_BRIDGE_COL: usize = HADDR_N_COLS + 5;
    const REL_T1_LO_SRC_IND_COL: usize = HADDR_N_COLS + 6;
    const REL_T1_LO_DST_IND_COL: usize = HADDR_N_COLS + 7;
    const REL_T1_LO_TRANS_IND_COL: usize = HADDR_N_COLS + 8;
    HAddrBlockParams {
        cols: HAddrBlockColumns {
            col_offset: base + REL_HADDR_SUBAIR_COL,
            window_indicator_col: base + REL_WINDOW_INDICATOR_COL,
            t1_hi_budget: T1LaneColumnBudget {
                bridge_col: base + REL_T1_HI_BRIDGE_COL,
                src_indicator_col: base + REL_T1_HI_SRC_IND_COL,
                dst_indicator_col: base + REL_T1_HI_DST_IND_COL,
                transition_indicator_col: base + REL_T1_HI_TRANS_IND_COL,
            },
            t1_lo_budget: T1LaneColumnBudget {
                bridge_col: base + REL_T1_LO_BRIDGE_COL,
                src_indicator_col: base + REL_T1_LO_SRC_IND_COL,
                dst_indicator_col: base + REL_T1_LO_DST_IND_COL,
                transition_indicator_col: base + REL_T1_LO_TRANS_IND_COL,
            },
        },
        row_window_start: 0,
        outer_n_cols,
        outer_log_rows: TX_VALIDITY_HAUTH_LOG_ROWS,
        t1_targets: HAddrBlockT1Targets {
            owner_hi_dst_col: SKEL_OPEN_COL_OFFSET + COL_OWNER_HI,
            owner_hi_dst_row: input,
            owner_lo_dst_col: SKEL_OPEN_COL_OFFSET + COL_OWNER_LO,
            owner_lo_dst_row: input,
        },
    }
}

// ---------------------------------------------------------------------------
// Column-shift adapter (local copy; same pattern as 5.3/5.4)
// ---------------------------------------------------------------------------

struct ShiftedColumnsConstraint {
    inner: Box<dyn Constraint>,
    shifted_cols: Vec<usize>,
    shifted_next: Vec<usize>,
}

impl ShiftedColumnsConstraint {
    fn new(inner: Box<dyn Constraint>, offset: usize, inner_n_cols: usize) -> Self {
        for &c in inner.columns() {
            assert!(c < inner_n_cols);
        }
        for &c in inner.shifted_columns() {
            assert!(c < inner_n_cols);
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

fn shift_public_column(pc: PublicColumn, offset: usize) -> PublicColumn {
    PublicColumn::new(pc.col + offset, pc.values)
}

// ---------------------------------------------------------------------------
// Composite
// ---------------------------------------------------------------------------

/// Stage 5.5 composite: combiner + FriStateOpen + N_INPUTS × HAddr
/// (T1) + N_INPUTS × HAuth (T2a per-input + T2b shared).
pub struct TxValidityCompositeHAuth {
    pub air: CompositeAir,
    combiner: FriStateCombinerComposite,
    open_witness: FriStateOpenWitness,
    open_public_columns: Vec<PublicColumn>,
    secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    /// Public tx-body-hash. Pinned on the shared T2b destinations.
    tx_body_hash: [Block128; 2],
    /// Per-input declared auth tag. Pinned on per-input T2a destinations.
    /// Computed from secret + tx_body_hash when building the test
    /// composite — but the composite accepts any `[(hi, lo)]` the
    /// caller supplies (matching the honest HAuth squeeze).
    auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
}

impl TxValidityCompositeHAuth {
    pub fn new(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
        tx_body_hash: [Block128; 2],
        auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    ) -> Self {
        let outer_n_cols = TX_VALIDITY_HAUTH_N_COLS;
        let outer_log_rows = TX_VALIDITY_HAUTH_LOG_ROWS;
        let outer_n_rows = 1usize << outer_log_rows;

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // Block A — combiner.
        let (combiner_constraints, combiner_publics) = clone_combiner_parts(&combiner);
        for c in combiner_constraints {
            constraints.push(Box::new(ShiftedColumnsConstraint::new(
                c,
                SKEL_COMBINER_COL_OFFSET,
                COMBINER_COMPOSITE_N_COLS,
            )));
        }
        for pc in combiner_publics {
            public_columns.push(shift_public_column(pc, SKEL_COMBINER_COL_OFFSET));
        }

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

        // Block C — HAddr × N_INPUTS + T1 bridges.
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let params = haddr_block_params_for(input, outer_n_cols);
            let wiring = emit_haddr_block(params);
            constraints.extend(wiring.constraints);
            public_columns.extend(wiring.public_columns);
        }

        // Block D — HAuth × N_INPUTS + T2a/T2b bridges.
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let params = hauth_block_params_for(input, outer_n_cols, tx_body_hash);
            let wiring = emit_hauth_block(params);
            constraints.extend(wiring.constraints);
            public_columns.extend(wiring.public_columns);
        }

        // Pin per-input T2a destinations to declared auth tags.
        // (T2b destinations are unpinned at 5.5 — see module doc.)
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let (hi_col, lo_col) = auth_tag_dst_cols(input);
            public_columns.push(PublicColumn::new(
                hi_col,
                pinned_row_programme(auth_tag_hi_dst_row(input), auth_tags[input][0], outer_n_rows),
            ));
            public_columns.push(PublicColumn::new(
                lo_col,
                pinned_row_programme(auth_tag_lo_dst_row(input), auth_tags[input][1], outer_n_rows),
            ));
        }

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
            tx_body_hash,
            auth_tags,
        }
    }

    /// Build an honest outer trace.
    pub fn build_trace(&self) -> Trace {
        let outer_n_rows = 1usize << TX_VALIDITY_HAUTH_LOG_ROWS;
        let mut cols: Vec<Vec<Block128>> = (0..TX_VALIDITY_HAUTH_N_COLS)
            .map(|_| vec![Block128::ZERO; outer_n_rows])
            .collect();

        // Combiner.
        let combiner_trace = self.combiner.build_trace();
        let combiner_cols = combiner_trace.columns;
        assert_eq!(combiner_cols.len(), COMBINER_COMPOSITE_N_COLS);
        for (i, src) in combiner_cols.into_iter().enumerate() {
            cols[SKEL_COMBINER_COL_OFFSET + i] = src;
        }

        // FriStateOpen.
        let open_inner =
            build_open_inner_cols(&self.open_witness, &self.open_public_columns);
        assert_eq!(open_inner.len(), FRI_STATE_OPEN_WITNESS_COLS);
        for (i, src) in open_inner.into_iter().enumerate() {
            let dst = &mut cols[SKEL_OPEN_COL_OFFSET + i];
            for (r, v) in src.into_iter().enumerate() {
                dst[r] = v;
            }
        }

        // HAddr blocks.
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let params = haddr_block_params_for(input, TX_VALIDITY_HAUTH_N_COLS);
            let _ = write_haddr_block_trace(&mut cols, params, self.secrets[input]);
        }

        // HAuth blocks.
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let params = hauth_block_params_for(
                input,
                TX_VALIDITY_HAUTH_N_COLS,
                self.tx_body_hash,
            );
            let _ = write_hauth_block_trace(&mut cols, params, self.secrets[input]);
        }

        // Final pass: overwrite every public column with its programme.
        // This plants the shared tx_body_hash dst cells + per-input
        // auth_tag dst cells to their declared values. Bridges then
        // force the HAuth blocks to match.
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

    pub fn tx_body_hash(&self) -> [Block128; 2] {
        self.tx_body_hash
    }

    pub fn auth_tags(&self) -> &[[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] {
        &self.auth_tags
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pinned_row_programme(row: usize, value: Block128, total_rows: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; total_rows];
    out[row] = value;
    out
}

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

/// Native auth-tag computation for a given `(secret, tx_body_hash)`.
/// Used by tests to populate the declared `auth_tags` array.
pub fn native_auth_tag(
    secret: [Block128; 2],
    tx_body_hash: [Block128; 2],
) -> [Block128; 2] {
    use crate::airs::hauth::{build_hauth_trace, extract_hauth_output};
    extract_hauth_output(&build_hauth_trace(secret, tx_body_hash))
}

/// Native address computation — mirrors 5.4 test helper.
pub fn native_address(secret: [Block128; 2]) -> [Block128; 2] {
    use crate::airs::haddr::{build_haddr_trace, extract_haddr_output};
    extract_haddr_output(&build_haddr_trace(secret))
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
    use crate::airs::hauth::{HAUTH_LAYOUT_C, HAUTH_OUTPUT_ROW};

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

    fn build() -> TxValidityCompositeHAuth {
        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);
        let prev_fields =
            extract_combiner_digest_fields(&build_combiner_side_trace(&prev_preimage), COMBINER_PERM_LAYOUT);
        let new_fields =
            extract_combiner_digest_fields(&build_combiner_side_trace(&new_preimage), COMBINER_PERM_LAYOUT);
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

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

        let tx_body_hash: [Block128; 2] = [
            Block128::from(0x1111_2222_3333_4444_u128),
            Block128::from(0x5555_6666_7777_8888_u128),
        ];

        let auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_auth_tag(secrets[0], tx_body_hash),
            native_auth_tag(secrets[1], tx_body_hash),
            native_auth_tag(secrets[2], tx_body_hash),
            native_auth_tag(secrets[3], tx_body_hash),
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

        TxValidityCompositeHAuth::new(
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
        )
    }

    #[test]
    fn layout_constants_agree() {
        assert_eq!(
            TX_VALIDITY_HAUTH_N_COLS,
            TX_VALIDITY_FULL_N_COLS
                + FRI_STATE_OPEN_N_INPUTS * HAUTH_BLOCK_OUTER_COLS
                + 2 * FRI_STATE_OPEN_N_INPUTS // per-input auth tag dsts
                + 2 * FRI_STATE_OPEN_N_INPUTS // per-input pre_s_B dsts
        );
        assert_eq!(HAUTH_BLOCK_OUTER_COLS, HAUTH_N_COLS + 17);
        assert_eq!(TX_VALIDITY_HAUTH_LOG_ROWS, TX_VALIDITY_FULL_LOG_ROWS);
    }

    #[test]
    fn honest_trace_accepts() {
        let comp = build();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    #[test]
    fn hauth_squeeze_matches_declared_tag_per_input() {
        let comp = build();
        let cols = comp.build_trace().columns;
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let base = full_hauth_block_base(input);
            let hi_col = base + HAUTH_LAYOUT_C.s;
            let lo_col = base + HAUTH_LAYOUT_C.s + 1;
            assert_eq!(cols[hi_col][HAUTH_OUTPUT_ROW], comp.auth_tags()[input][0]);
            assert_eq!(cols[lo_col][HAUTH_OUTPUT_ROW], comp.auth_tags()[input][1]);
        }
    }

    #[test]
    fn t2a_hi_declared_tag_tamper_rejects() {
        // Tampering the declared PI pin on auth_tag_hi[0] without
        // rebuilding the composite would fail — but we simulate the
        // attacker who flips the trace dst cell directly. The
        // PublicColumn pin catches it.
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (hi_col, _lo_col) = auth_tag_dst_cols(0);
        cols[hi_col][auth_tag_hi_dst_row(0)] =
            cols[hi_col][auth_tag_hi_dst_row(0)] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t2a_lo_declared_tag_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (_hi_col, lo_col) = auth_tag_dst_cols(2);
        cols[lo_col][auth_tag_lo_dst_row(2)] =
            cols[lo_col][auth_tag_lo_dst_row(2)] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t2b_pre_s_b_hi_dst_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (hi_col, _) = pre_s_b_dst_cols(1);
        let row = pre_s_b_hi_dst_row(1);
        cols[hi_col][row] = cols[hi_col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t2b_pre_s_b_lo_dst_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (_, lo_col) = pre_s_b_dst_cols(3);
        let row = pre_s_b_lo_dst_row(3);
        cols[lo_col][row] = cols[lo_col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_interior_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let base = full_hauth_block_base(1);
        use crate::airs::hauth::HAUTH_LAYOUT_A;
        let col = base + HAUTH_LAYOUT_A.sout + 2;
        cols[col][5] = cols[col][5] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_squeeze_cell_tamper_rejects() {
        // Tamper input 2's HAuth squeeze hi. The permutation constraints
        // catch it directly; even if they didn't, the T2a bridge would.
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let base = full_hauth_block_base(2);
        let col = base + HAUTH_LAYOUT_C.s;
        cols[col][HAUTH_OUTPUT_ROW] = cols[col][HAUTH_OUTPUT_ROW] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn per_input_t2b_dsts_are_disjoint() {
        // Sanity: at 5.5 each block's T2b dst is its own pair (per
        // module doc). Sharing is deferred to 5.7.
        use std::collections::HashSet;
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let p = hauth_block_params_for(input, TX_VALIDITY_HAUTH_N_COLS, [Block128::ZERO; 2]);
            assert!(seen.insert((p.targets.tx_body_hi_dst_col, p.targets.tx_body_hi_dst_row)));
            assert!(seen.insert((p.targets.tx_body_lo_dst_col, p.targets.tx_body_lo_dst_row)));
        }
    }

    #[test]
    fn t1_still_active_owner_tamper_rejects() {
        // Stage 5.4 T1 ties must still fire in the 5.5 composite.
        let comp = build();
        let mut cols = comp.build_trace().columns;
        cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] =
            cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }
}
