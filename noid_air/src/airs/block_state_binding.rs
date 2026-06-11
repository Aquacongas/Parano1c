// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(
    clippy::needless_range_loop,
    clippy::identity_op,
    clippy::manual_memcpy
)]

//! `BlockStateBindingAir` — block-level state opening AIR (S.5).
//!
//! Replaces the per-tx `FriStateOpenAir` with a single block-scoped AIR
//! that proves correctness of ALL slot openings across N transactions.
//!
//! ## Architecture
//!
//! The AIR handles:
//! - **Eq-ladder + gamma-RLC batching**: all slot openings (inputs + outputs
//!   from all txs) are batched into a single FRI claim via γ-weighted
//!   prefix-sum, binding opened pre-state values to `prev_state_root`.
//! - **Delta identity + delta-acc**: proves net state change matches
//!   `prev_f_L(r) ⊕ new_f_L(r)` for each lane, binding to `new_state_root`.
//! - **Pre-state source gating**: `opened_pre = is_spend · claim_triple`
//!   (spend rows read claimed value; mint rows force zero pre-state).
//!
//! ## What lives OUTSIDE this AIR (Kill-Shot GKR)
//!
//! - **C_claimed bridge**: verified by a separate Poseidon2b Kill-Shot
//!   that binds each tx's opened slots to its `claims_commitment`.
//! - **Merkle paths** from column FRI roots to `state_root`: verified by
//!   Merkle Kill-Shot GKR (14-var unified sumcheck).
//!
//!
//! - Fused `TripleProductGate` (degree-3) for `gp_lane = γ^i · eq_{L-1} ·
//!   opened_pre_lane` — eliminates 3 intermediate columns.
//! - Fused `TripleProductGate` for `eq_delta_lane = eq_{L-1} · live_mask ·
//!   delta_lane` — eliminates 3 intermediate columns.
//! - `EqLadderStepGate` for eq-ladder — eliminates L-1 intermediate columns.
//! - Shared row indicators across boundary pins — amortises MLE re-eval.
//! - Shared `acc_step_indicator` for both gamma-acc and delta-acc recurrences.
//! - PublicColumn for eval_point and gamma_powers — verifier computes, prover
//!   pins without extra constraints.

use crate::gates::{
    multi_row_indicator_programme, row_indicator_programme, BoolGate, EqLadderStepGate, MulGate,
    PublicColumn, SelectorGate, TripleProductGate, WeightedLinearGate, WeightedLinearGateShifted,
};
use crate::{Air, Constraint};
use noid_core::{Block128, TowerField};

// =============================================================================
// Constants
// =============================================================================

/// Default log2 of state depth. Production: 24 (16M slots).
/// For testing: 4 (16 slots).
pub const BLOCK_STATE_BINDING_LOG_SLOTS: usize = 4;

/// Maximum slots per block (inputs + outputs across all txs).
/// 100 txs × (4 inputs + 8 outputs) = 1200. Padded to next power of 2 = 2048.
pub const BLOCK_STATE_BINDING_MAX_SLOTS: usize = 2048;

/// Log2 of max slots (trace height).
pub const BLOCK_STATE_BINDING_LOG_ROWS: usize = 11; // 2^11 = 2048

/// Actual trace row count.
pub const BLOCK_STATE_BINDING_N_ROWS: usize = 1 << BLOCK_STATE_BINDING_LOG_ROWS;

// =============================================================================
// Column layout
// =============================================================================
//
// Per-slot row carries:
//   value, owner_hi, owner_lo            — claim triple (pinned by boundary ties)
//   idx_bit_0 .. idx_bit_{L-1}           — slot-index bits (BoolGate pinned)
//   delta_value, delta_hi, delta_lo      — XOR-delta for state transition
//   live_mask                            — {0,1} action-union
//   is_spend, is_mint                    — mutually-exclusive action selectors
//   opened_pre_value, opened_pre_hi,
//     opened_pre_lo                      — gated pre-state: is_spend · claim_lane
//   eq_delta_value, eq_delta_hi,
//     eq_delta_lo                        — fused: eq_{L-1} · live_mask · delta_lane
//   delta_acc_value, delta_acc_hi,
//     delta_acc_lo                       — prefix-sum for state-change proof
//   eval_point_0 .. eval_point_{L-1}     — transcript-derived r (PublicColumn)
//   eq_0 .. eq_{L-1}                     — eq-ladder columns
//   gamma_powers                         — γ^row (PublicColumn)
//   gp_value, gp_hi, gp_lo              — fused: γ^i · eq_{L-1} · opened_pre_lane
//   acc_value, acc_hi, acc_lo            — gamma-RLC prefix-sum
//   row_indicator_0 .. row_indicator_{N-1} — shared single-hot indicators
//   acc_step_indicator                   — multi-hot for shifted recurrences

pub const COL_VALUE: usize = 0;
pub const COL_OWNER_HI: usize = 1;
pub const COL_OWNER_LO: usize = 2;
pub const COL_IDX_BIT_BASE: usize = 3;

// Offsets relative to COL_IDX_BIT_BASE + log_slots:
pub const COL_DELTA_VALUE_OFFSET: usize = 0;
pub const COL_DELTA_OWNER_HI_OFFSET: usize = 1;
pub const COL_DELTA_OWNER_LO_OFFSET: usize = 2;
pub const COL_LIVE_MASK_OFFSET: usize = 3;
pub const COL_IS_SPEND_OFFSET: usize = 4;
pub const COL_IS_MINT_OFFSET: usize = 5;
pub const COL_OPENED_PRE_VALUE_OFFSET: usize = 6;
pub const COL_OPENED_PRE_OWNER_HI_OFFSET: usize = 7;
pub const COL_OPENED_PRE_OWNER_LO_OFFSET: usize = 8;
pub const COL_EQ_DELTA_VALUE_OFFSET: usize = 9;
pub const COL_EQ_DELTA_OWNER_HI_OFFSET: usize = 10;
pub const COL_EQ_DELTA_OWNER_LO_OFFSET: usize = 11;
pub const COL_DELTA_ACC_VALUE_OFFSET: usize = 12;
pub const COL_DELTA_ACC_OWNER_HI_OFFSET: usize = 13;
pub const COL_DELTA_ACC_OWNER_LO_OFFSET: usize = 14;
// After these 15 fixed offsets, eval_point columns start:
pub const COL_EVAL_POINT_BASE_OFFSET: usize = 15;
// eq_ladder starts at COL_EVAL_POINT_BASE_OFFSET + log_slots
// gamma_powers at eq_ladder_base + log_slots
// gp lanes at gamma_powers + 1
// acc lanes at gp + 3
// row indicators at acc + 3
// acc_step_indicator at row_indicators + n_live_slots

// =============================================================================
// Layout
// =============================================================================

/// Parameterises the AIR shape for different block sizes and state depths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockStateBindingLayout {
    /// Number of live slot rows (inputs + outputs from all txs in block).
    pub n_slots: usize,
    /// log2 of trace height (>= ceil_log2(n_slots)).
    pub log_rows: usize,
    /// log2 of chain state depth (e.g. 24 for mainnet, 4 for test).
    pub log_slots: usize,
}

impl BlockStateBindingLayout {
    pub const DEFAULT: Self = Self {
        n_slots: 4,
        log_rows: 3,
        log_slots: BLOCK_STATE_BINDING_LOG_SLOTS,
    };

    pub const fn n_rows(&self) -> usize {
        1 << self.log_rows
    }

    /// Total number of witness + public columns in this layout.
    pub const fn n_cols(&self) -> usize {
        // 3 claim lanes + log_slots idx bits + 15 fixed columns
        // + log_slots eval_point + log_slots eq_ladder + 1 gamma_powers
        // + 3 gp lanes + 3 acc lanes + n_rows row indicators + 1 acc_step
        // n_rows is FIXED per block (same log_rows for all segments),
        // ensuring all state binding AIRs have identical n_cols.
        3 + self.log_slots + 15 + self.log_slots + self.log_slots + 1 + 3 + 3 + self.n_rows() + 1
    }

    // Column accessors

    pub const fn col_idx_bit(&self, k: usize) -> usize {
        COL_IDX_BIT_BASE + k
    }

    const fn section_base(&self) -> usize {
        COL_IDX_BIT_BASE + self.log_slots
    }

    pub const fn col_delta_value(&self) -> usize {
        self.section_base() + COL_DELTA_VALUE_OFFSET
    }
    pub const fn col_delta_owner_hi(&self) -> usize {
        self.section_base() + COL_DELTA_OWNER_HI_OFFSET
    }
    pub const fn col_delta_owner_lo(&self) -> usize {
        self.section_base() + COL_DELTA_OWNER_LO_OFFSET
    }
    pub const fn col_live_mask(&self) -> usize {
        self.section_base() + COL_LIVE_MASK_OFFSET
    }
    pub const fn col_is_spend(&self) -> usize {
        self.section_base() + COL_IS_SPEND_OFFSET
    }
    pub const fn col_is_mint(&self) -> usize {
        self.section_base() + COL_IS_MINT_OFFSET
    }
    pub const fn col_opened_pre_value(&self) -> usize {
        self.section_base() + COL_OPENED_PRE_VALUE_OFFSET
    }
    pub const fn col_opened_pre_owner_hi(&self) -> usize {
        self.section_base() + COL_OPENED_PRE_OWNER_HI_OFFSET
    }
    pub const fn col_opened_pre_owner_lo(&self) -> usize {
        self.section_base() + COL_OPENED_PRE_OWNER_LO_OFFSET
    }
    pub const fn col_eq_delta_value(&self) -> usize {
        self.section_base() + COL_EQ_DELTA_VALUE_OFFSET
    }
    pub const fn col_eq_delta_owner_hi(&self) -> usize {
        self.section_base() + COL_EQ_DELTA_OWNER_HI_OFFSET
    }
    pub const fn col_eq_delta_owner_lo(&self) -> usize {
        self.section_base() + COL_EQ_DELTA_OWNER_LO_OFFSET
    }
    pub const fn col_delta_acc_value(&self) -> usize {
        self.section_base() + COL_DELTA_ACC_VALUE_OFFSET
    }
    pub const fn col_delta_acc_owner_hi(&self) -> usize {
        self.section_base() + COL_DELTA_ACC_OWNER_HI_OFFSET
    }
    pub const fn col_delta_acc_owner_lo(&self) -> usize {
        self.section_base() + COL_DELTA_ACC_OWNER_LO_OFFSET
    }

    pub const fn col_eval_point(&self, k: usize) -> usize {
        self.section_base() + COL_EVAL_POINT_BASE_OFFSET + k
    }

    pub const fn col_eq_ladder(&self, k: usize) -> usize {
        self.section_base() + COL_EVAL_POINT_BASE_OFFSET + self.log_slots + k
    }

    pub const fn col_gamma_powers(&self) -> usize {
        self.col_eq_ladder(0) + self.log_slots
    }

    pub const fn col_gp_value(&self) -> usize {
        self.col_gamma_powers() + 1
    }
    pub const fn col_gp_owner_hi(&self) -> usize {
        self.col_gamma_powers() + 2
    }
    pub const fn col_gp_owner_lo(&self) -> usize {
        self.col_gamma_powers() + 3
    }

    pub const fn col_acc_value(&self) -> usize {
        self.col_gamma_powers() + 4
    }
    pub const fn col_acc_owner_hi(&self) -> usize {
        self.col_gamma_powers() + 5
    }
    pub const fn col_acc_owner_lo(&self) -> usize {
        self.col_gamma_powers() + 6
    }

    pub const fn col_row_indicator(&self, r: usize) -> usize {
        self.col_gamma_powers() + 7 + r
    }

    pub const fn col_acc_step_indicator(&self) -> usize {
        self.col_gamma_powers() + 7 + self.n_rows()
    }
}

// =============================================================================
// Claim & Witness
// =============================================================================

/// One row's worth of witness data for a single slot opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockStateBindingClaim {
    pub slot_index: u32,
    pub value: Block128,
    pub owner_hi: Block128,
    pub owner_lo: Block128,
    pub delta_value: Block128,
    pub delta_owner_hi: Block128,
    pub delta_owner_lo: Block128,
    pub is_spend: bool,
    pub is_mint: bool,
}

impl BlockStateBindingClaim {
    pub const EMPTY: Self = Self {
        slot_index: 0,
        value: Block128(0),
        owner_hi: Block128(0),
        owner_lo: Block128(0),
        delta_value: Block128(0),
        delta_owner_hi: Block128(0),
        delta_owner_lo: Block128(0),
        is_spend: false,
        is_mint: false,
    };

    pub const fn live(&self) -> bool {
        self.is_spend || self.is_mint
    }

    /// Build a spend claim: input slot with known pre-state values.
    /// Delta for spend: pre XOR post(=0) = pre = value itself.
    pub fn spend(slot_index: u32, value: Block128, owner_hi: Block128, owner_lo: Block128) -> Self {
        Self {
            slot_index,
            value,
            owner_hi,
            owner_lo,
            delta_value: value,
            delta_owner_hi: owner_hi,
            delta_owner_lo: owner_lo,
            is_spend: true,
            is_mint: false,
        }
    }

    /// Build a mint claim: output slot, pre-state must be EMPTY.
    /// Delta for mint: pre(=0) XOR post = post = value itself.
    pub fn mint(slot_index: u32, value: Block128, owner_hi: Block128, owner_lo: Block128) -> Self {
        Self {
            slot_index,
            value,
            owner_hi,
            owner_lo,
            delta_value: value,
            delta_owner_hi: owner_hi,
            delta_owner_lo: owner_lo,
            is_spend: false,
            is_mint: true,
        }
    }
}

/// Full witness bundle for the block-level state binding AIR.
#[derive(Debug, Clone)]
pub struct BlockStateBindingWitness {
    pub layout: BlockStateBindingLayout,
    pub claims: Vec<BlockStateBindingClaim>,
    /// Transcript-derived MLE evaluation point (one coordinate per log_slots dimension).
    pub eval_point: Vec<Block128>,
    /// Fiat-Shamir batching challenge for gamma-RLC.
    pub gamma: Block128,
    /// PCS openings of the three state columns at eval_point under prev_state_root.
    pub prev_lane_openings: [Block128; 3],
    /// PCS openings of the three state columns at eval_point under new_state_root.
    pub new_lane_openings: [Block128; 3],
}

impl BlockStateBindingWitness {
    pub fn new(
        claims: Vec<BlockStateBindingClaim>,
        eval_point: Vec<Block128>,
        gamma: Block128,
        prev_lane_openings: [Block128; 3],
        new_lane_openings: [Block128; 3],
    ) -> Self {
        let n_slots = claims.len();
        let log_slots = eval_point.len();
        // Minimum log_rows = TAU+1 = 9 (required by VSHIFT in the algebraic STARK).
        // Using actual ceil_log2(n_slots) ensures the circuit is as small as possible
        // while satisfying the constraint.  BLOCK_STATE_BINDING_LOG_ROWS=11 is the
        // capacity limit, not the floor — using it for small claim counts wastes
        // 2^11 row-indicator columns (64 MB trace) instead of ~2^9 (4 MB).
        const VSHIFT_MIN_LOG_ROWS: usize = 9; // TAU+1 where TAU=8
        let log_rows = ceil_log2(n_slots.max(2)).max(VSHIFT_MIN_LOG_ROWS);
        let layout = BlockStateBindingLayout {
            n_slots,
            log_rows,
            log_slots,
        };
        Self {
            layout,
            claims,
            eval_point,
            gamma,
            prev_lane_openings,
            new_lane_openings,
        }
    }

    pub fn with_layout(
        claims: Vec<BlockStateBindingClaim>,
        eval_point: Vec<Block128>,
        gamma: Block128,
        prev_lane_openings: [Block128; 3],
        new_lane_openings: [Block128; 3],
        layout: BlockStateBindingLayout,
    ) -> Self {
        Self {
            layout,
            claims,
            eval_point,
            gamma,
            prev_lane_openings,
            new_lane_openings,
        }
    }

    /// Compute the expected batched gamma-RLC claims the AIR's terminal
    /// accumulator cells must equal:
    ///   `expected_lane = Σ_i γ^i · eq(r, slot_bits_i) · opened_pre_lane_i`
    pub fn expected_batched_claims(&self) -> [Block128; 3] {
        let mut gamma_pow = Block128::ONE;
        let mut acc = [Block128::ZERO; 3];
        let n_rows = self.layout.n_rows();
        for i in 0..n_rows {
            let claim = if i < self.claims.len() {
                &self.claims[i]
            } else {
                &BlockStateBindingClaim::EMPTY
            };
            let (pre_value, pre_hi, pre_lo) = if claim.is_spend {
                (claim.value, claim.owner_hi, claim.owner_lo)
            } else {
                (Block128::ZERO, Block128::ZERO, Block128::ZERO)
            };
            let mut eq = Block128::ONE;
            let mut idx = claim.slot_index as usize;
            for k in 0..self.layout.log_slots {
                let bit = Block128::from((idx & 1) as u128);
                idx >>= 1;
                eq *= Block128::ONE + self.eval_point[k] + bit;
            }
            acc[0] += gamma_pow * eq * pre_value;
            acc[1] += gamma_pow * eq * pre_hi;
            acc[2] += gamma_pow * eq * pre_lo;
            gamma_pow *= self.gamma;
        }
        acc
    }

    /// Compute expected new_lane_openings given prev_lane_openings:
    ///   `new_lane = prev_lane + Σ_i eq(r, slot_bits_i) · live_i · delta_lane_i`
    pub fn expected_new_lane_openings(&self, prev: [Block128; 3]) -> [Block128; 3] {
        let mut acc = [Block128::ZERO; 3];
        let n_rows = self.layout.n_rows();
        for i in 0..n_rows {
            let claim = if i < self.claims.len() {
                &self.claims[i]
            } else {
                &BlockStateBindingClaim::EMPTY
            };
            if !claim.live() {
                continue;
            }
            let mut eq = Block128::ONE;
            let mut idx = claim.slot_index as usize;
            for k in 0..self.layout.log_slots {
                let bit = Block128::from((idx & 1) as u128);
                idx >>= 1;
                eq *= Block128::ONE + self.eval_point[k] + bit;
            }
            acc[0] += eq * claim.delta_value;
            acc[1] += eq * claim.delta_owner_hi;
            acc[2] += eq * claim.delta_owner_lo;
        }
        [prev[0] + acc[0], prev[1] + acc[1], prev[2] + acc[2]]
    }

    /// Populate all trace columns from the witness data.
    pub fn build_columns(&self) -> Vec<Vec<Block128>> {
        let layout = self.layout;
        let n_cols = layout.n_cols();
        let n_rows = layout.n_rows();
        let log_slots = layout.log_slots;
        let n_slots = layout.n_slots;

        let mut cols = vec![vec![Block128::ZERO; n_rows]; n_cols];

        // Pad claims to trace height
        let mut padded_claims: Vec<BlockStateBindingClaim> = self.claims.clone();
        padded_claims.resize(n_rows, BlockStateBindingClaim::EMPTY);

        // Compute gamma powers: γ^0, γ^1, ..., γ^{n_rows-1}
        let mut gamma_powers = vec![Block128::ONE; n_rows];
        for i in 1..n_rows {
            gamma_powers[i] = gamma_powers[i - 1] * self.gamma;
        }

        // Fill columns row by row
        for row in 0..n_rows {
            let claim = &padded_claims[row];

            // Claim triple
            cols[COL_VALUE][row] = claim.value;
            cols[COL_OWNER_HI][row] = claim.owner_hi;
            cols[COL_OWNER_LO][row] = claim.owner_lo;

            // Slot index bits
            for b in 0..log_slots {
                let bit = (claim.slot_index >> b) & 1;
                cols[layout.col_idx_bit(b)][row] = Block128::from(bit as u128);
            }

            // Delta columns
            cols[layout.col_delta_value()][row] = claim.delta_value;
            cols[layout.col_delta_owner_hi()][row] = claim.delta_owner_hi;
            cols[layout.col_delta_owner_lo()][row] = claim.delta_owner_lo;

            // Action flags
            let live = claim.live();
            cols[layout.col_live_mask()][row] = Block128::from(live as u128);
            cols[layout.col_is_spend()][row] = Block128::from(claim.is_spend as u128);
            cols[layout.col_is_mint()][row] = Block128::from(claim.is_mint as u128);

            // Opened pre-state: is_spend · claim_lane
            let is_spend_f = Block128::from(claim.is_spend as u128);
            cols[layout.col_opened_pre_value()][row] = is_spend_f * claim.value;
            cols[layout.col_opened_pre_owner_hi()][row] = is_spend_f * claim.owner_hi;
            cols[layout.col_opened_pre_owner_lo()][row] = is_spend_f * claim.owner_lo;

            // Eq-ladder: eq_k = product_{j<=k} (1 + r_j + b_j)
            let mut eq_val = Block128::ONE;
            for k in 0..log_slots {
                let r_k = self.eval_point[k];
                let b_k = cols[layout.col_idx_bit(k)][row];
                eq_val = eq_val * (Block128::ONE + r_k + b_k);
                cols[layout.col_eq_ladder(k)][row] = eq_val;
            }
            let eq_tail = eq_val; // eq_{L-1}

            // Fused eq_delta_lane = eq_{L-1} · live_mask · delta_lane
            let live_f = Block128::from(live as u128);
            cols[layout.col_eq_delta_value()][row] = eq_tail * live_f * claim.delta_value;
            cols[layout.col_eq_delta_owner_hi()][row] = eq_tail * live_f * claim.delta_owner_hi;
            cols[layout.col_eq_delta_owner_lo()][row] = eq_tail * live_f * claim.delta_owner_lo;

            // Gamma-weighted MLE product: gp_lane = γ^i · eq_{L-1} · opened_pre_lane
            let gp_factor = gamma_powers[row] * eq_tail;
            cols[layout.col_gp_value()][row] = gp_factor * cols[layout.col_opened_pre_value()][row];
            cols[layout.col_gp_owner_hi()][row] =
                gp_factor * cols[layout.col_opened_pre_owner_hi()][row];
            cols[layout.col_gp_owner_lo()][row] =
                gp_factor * cols[layout.col_opened_pre_owner_lo()][row];
        }

        // Prefix-sum accumulators (gamma-RLC)
        for lane in 0..3 {
            let gp_col = match lane {
                0 => layout.col_gp_value(),
                1 => layout.col_gp_owner_hi(),
                _ => layout.col_gp_owner_lo(),
            };
            let acc_col = match lane {
                0 => layout.col_acc_value(),
                1 => layout.col_acc_owner_hi(),
                _ => layout.col_acc_owner_lo(),
            };
            cols[acc_col][0] = cols[gp_col][0];
            for i in 1..n_rows {
                cols[acc_col][i] = cols[acc_col][i - 1] + cols[gp_col][i];
            }
        }

        // Prefix-sum accumulators (delta)
        for lane in 0..3 {
            let eq_delta_col = match lane {
                0 => layout.col_eq_delta_value(),
                1 => layout.col_eq_delta_owner_hi(),
                _ => layout.col_eq_delta_owner_lo(),
            };
            let delta_acc_col = match lane {
                0 => layout.col_delta_acc_value(),
                1 => layout.col_delta_acc_owner_hi(),
                _ => layout.col_delta_acc_owner_lo(),
            };
            cols[delta_acc_col][0] = cols[eq_delta_col][0];
            for i in 1..n_rows {
                cols[delta_acc_col][i] = cols[delta_acc_col][i - 1] + cols[eq_delta_col][i];
            }
        }

        // Public columns: eval_point (constant per row)
        for k in 0..log_slots {
            let col = layout.col_eval_point(k);
            for row in 0..n_rows {
                cols[col][row] = self.eval_point[k];
            }
        }

        // Public column: gamma_powers
        let gp_col = layout.col_gamma_powers();
        for row in 0..n_rows {
            cols[gp_col][row] = gamma_powers[row];
        }

        // Row indicators (single-hot) — one column per row in the trace.
        for r in 0..n_rows {
            let col = layout.col_row_indicator(r);
            let prog = row_indicator_programme(r, n_rows);
            for (i, v) in prog.iter().enumerate() {
                cols[col][i] = *v;
            }
        }

        // Acc-step indicator: multi-hot on rows 0..n_slots-1
        let step_col = layout.col_acc_step_indicator();
        let step_rows: Vec<usize> = (0..n_slots.saturating_sub(1)).collect();
        let step_prog = multi_row_indicator_programme(&step_rows, n_rows);
        for (i, v) in step_prog.iter().enumerate() {
            cols[step_col][i] = *v;
        }

        cols
    }
}

// =============================================================================
// AIR struct
// =============================================================================

pub struct BlockStateBindingAir {
    layout: BlockStateBindingLayout,
    n_cols: usize,
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
    /// Stored for FRI opening cross-check.
    pub eval_point: Vec<Block128>,
    pub prev_lane_openings: [Block128; 3],
    pub new_lane_openings: [Block128; 3],
}

impl BlockStateBindingAir {
    pub fn new(
        claims: &[BlockStateBindingClaim],
        prev_lane_openings: [Block128; 3],
        new_lane_openings: [Block128; 3],
        eval_point: &[Block128],
        gamma: Block128,
        expected_batched_claims: [Block128; 3],
    ) -> Self {
        let n_slots = claims.len();
        let log_slots = eval_point.len();
        // Minimum log_rows = TAU+1 = 9 (VSHIFT constraint). Use actual size.
        const VSHIFT_MIN_LOG_ROWS: usize = 9;
        let log_rows = ceil_log2(n_slots.max(2)).max(VSHIFT_MIN_LOG_ROWS);
        let layout = BlockStateBindingLayout {
            n_slots,
            log_rows,
            log_slots,
        };
        Self::new_with_layout(
            claims,
            prev_lane_openings,
            new_lane_openings,
            eval_point,
            gamma,
            expected_batched_claims,
            layout,
        )
    }

    pub fn new_with_layout(
        claims: &[BlockStateBindingClaim],
        prev_lane_openings: [Block128; 3],
        new_lane_openings: [Block128; 3],
        eval_point: &[Block128],
        gamma: Block128,
        expected_batched_claims: [Block128; 3],
        layout: BlockStateBindingLayout,
    ) -> Self {
        assert!(
            claims.len() <= layout.n_rows(),
            "BlockStateBindingAir: claims exceed trace height"
        );
        assert_eq!(
            eval_point.len(),
            layout.log_slots,
            "BlockStateBindingAir: eval_point length mismatch"
        );

        let n_rows = layout.n_rows();
        let log_slots = layout.log_slots;
        let n_slots = layout.n_slots;
        let n_cols = layout.n_cols();

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // =====================================================================
        // 1. Boolean gates: idx bits, live_mask, is_spend, is_mint
        // =====================================================================
        for b in 0..log_slots {
            constraints.push(Box::new(BoolGate::new(layout.col_idx_bit(b))));
        }
        constraints.push(Box::new(BoolGate::new(layout.col_live_mask())));
        constraints.push(Box::new(BoolGate::new(layout.col_is_spend())));
        constraints.push(Box::new(BoolGate::new(layout.col_is_mint())));

        // =====================================================================
        // 2. Action exclusivity: is_spend · is_mint == 0
        //    Expressed as SelectorGate(is_spend, is_mint == 0).
        // =====================================================================
        constraints.push(Box::new(SelectorGate::new(
            layout.col_is_spend(),
            Box::new(WeightedLinearGate::new(
                vec![(layout.col_is_mint(), Block128::ONE)],
                Block128::ZERO,
            )),
        )));

        // =====================================================================
        // 3. Action union: live_mask + is_spend + is_mint == 0
        //    (char-2: live_mask = is_spend XOR is_mint, which under exclusivity
        //     equals is_spend + is_mint)
        // =====================================================================
        constraints.push(Box::new(WeightedLinearGate::new_xor(vec![
            layout.col_live_mask(),
            layout.col_is_spend(),
            layout.col_is_mint(),
        ])));

        // =====================================================================
        // 4. Delta identity: live_mask · (value + delta_lane) == 0 per lane
        //    Encodes: on live rows, delta = value (for both spend and mint).
        // =====================================================================
        constraints.push(Box::new(SelectorGate::new(
            layout.col_live_mask(),
            Box::new(WeightedLinearGate::new_xor(vec![
                layout.col_delta_value(),
                COL_VALUE,
            ])),
        )));
        constraints.push(Box::new(SelectorGate::new(
            layout.col_live_mask(),
            Box::new(WeightedLinearGate::new_xor(vec![
                layout.col_delta_owner_hi(),
                COL_OWNER_HI,
            ])),
        )));
        constraints.push(Box::new(SelectorGate::new(
            layout.col_live_mask(),
            Box::new(WeightedLinearGate::new_xor(vec![
                layout.col_delta_owner_lo(),
                COL_OWNER_LO,
            ])),
        )));

        // =====================================================================
        // 5. Pre-state source: opened_pre_lane == is_spend · claim_lane
        //    (MulGate per lane)
        // =====================================================================
        constraints.push(Box::new(MulGate::new(
            layout.col_opened_pre_value(),
            layout.col_is_spend(),
            COL_VALUE,
        )));
        constraints.push(Box::new(MulGate::new(
            layout.col_opened_pre_owner_hi(),
            layout.col_is_spend(),
            COL_OWNER_HI,
        )));
        constraints.push(Box::new(MulGate::new(
            layout.col_opened_pre_owner_lo(),
            layout.col_is_spend(),
            COL_OWNER_LO,
        )));

        // =====================================================================
        // 6. Eq-ladder: eq_0 = 1 + r_0 + b_0 (linear), then
        //    eq_k = eq_{k-1} · (1 + r_k + b_k) for k >= 1 (fused EqLadderStep)
        // =====================================================================
        // Constraint 0: eq_0 + r_0 + b_0 + 1 == 0
        constraints.push(Box::new(WeightedLinearGate::new(
            vec![
                (layout.col_eq_ladder(0), Block128::ONE),
                (layout.col_eval_point(0), Block128::ONE),
                (layout.col_idx_bit(0), Block128::ONE),
            ],
            Block128::ONE,
        )));
        // Steps 1..L-1
        for k in 1..log_slots {
            constraints.push(Box::new(EqLadderStepGate::new(
                layout.col_eq_ladder(k),
                layout.col_eq_ladder(k - 1),
                layout.col_eval_point(k),
                layout.col_idx_bit(k),
            )));
        }

        // =====================================================================
        // 7. Fused eq_delta: eq_delta_lane = eq_{L-1} · live_mask · delta_lane
        //    (TripleProductGate per lane, degree 3)
        // =====================================================================
        let eq_tail_col = layout.col_eq_ladder(log_slots - 1);
        constraints.push(Box::new(TripleProductGate::new(
            layout.col_eq_delta_value(),
            eq_tail_col,
            layout.col_live_mask(),
            layout.col_delta_value(),
        )));
        constraints.push(Box::new(TripleProductGate::new(
            layout.col_eq_delta_owner_hi(),
            eq_tail_col,
            layout.col_live_mask(),
            layout.col_delta_owner_hi(),
        )));
        constraints.push(Box::new(TripleProductGate::new(
            layout.col_eq_delta_owner_lo(),
            eq_tail_col,
            layout.col_live_mask(),
            layout.col_delta_owner_lo(),
        )));

        // =====================================================================
        // 8. Fused gamma-weighted MLE product:
        //    gp_lane = γ^i · eq_{L-1} · opened_pre_lane
        //    (TripleProductGate per lane, degree 3)
        // =====================================================================
        constraints.push(Box::new(TripleProductGate::new(
            layout.col_gp_value(),
            layout.col_gamma_powers(),
            eq_tail_col,
            layout.col_opened_pre_value(),
        )));
        constraints.push(Box::new(TripleProductGate::new(
            layout.col_gp_owner_hi(),
            layout.col_gamma_powers(),
            eq_tail_col,
            layout.col_opened_pre_owner_hi(),
        )));
        constraints.push(Box::new(TripleProductGate::new(
            layout.col_gp_owner_lo(),
            layout.col_gamma_powers(),
            eq_tail_col,
            layout.col_opened_pre_owner_lo(),
        )));

        // =====================================================================
        // 9. Gamma-RLC prefix-sum: acc_lane[0] = gp_lane[0] (row-0 pin)
        //    acc_lane[i+1] = acc_lane[i] + gp_lane[i+1] (shifted recurrence)
        // =====================================================================
        // Row-0 pins: acc_lane[0] + gp_lane[0] == 0 (gated by row_indicator(0))
        let row0_prog = row_indicator_programme(0, n_rows);
        let row0_col = layout.col_row_indicator(0);
        public_columns.push(PublicColumn {
            col: row0_col,
            values: row0_prog.clone(),
        });

        for (acc_c, gp_c) in [
            (layout.col_acc_value(), layout.col_gp_value()),
            (layout.col_acc_owner_hi(), layout.col_gp_owner_hi()),
            (layout.col_acc_owner_lo(), layout.col_gp_owner_lo()),
        ] {
            constraints.push(Box::new(SelectorGate::new(
                row0_col,
                Box::new(WeightedLinearGate::new_xor(vec![acc_c, gp_c])),
            )));
        }

        // Shifted recurrence: acc[i+1] = acc[i] + gp[i+1], gated by step indicator
        let step_rows: Vec<usize> = (0..n_slots.saturating_sub(1)).collect();
        let step_prog = multi_row_indicator_programme(&step_rows, n_rows);
        let step_col = layout.col_acc_step_indicator();
        public_columns.push(PublicColumn {
            col: step_col,
            values: step_prog,
        });

        for (acc_c, gp_c) in [
            (layout.col_acc_value(), layout.col_gp_value()),
            (layout.col_acc_owner_hi(), layout.col_gp_owner_hi()),
            (layout.col_acc_owner_lo(), layout.col_gp_owner_lo()),
        ] {
            // acc[i] + acc[i+1] + gp[i+1] == 0 (char-2 XOR addition)
            constraints.push(Box::new(SelectorGate::new(
                step_col,
                Box::new(WeightedLinearGateShifted::new(
                    vec![(acc_c, Block128::ONE)],
                    vec![(acc_c, Block128::ONE), (gp_c, Block128::ONE)],
                    Block128::ZERO,
                )),
            )));
        }

        // Terminal closure: acc_lane[n_slots-1] == expected_batched_claims[lane]
        let terminal_row = n_slots.saturating_sub(1);
        let terminal_prog = row_indicator_programme(terminal_row, n_rows);
        let terminal_col = layout.col_row_indicator(terminal_row);
        if terminal_row != 0 {
            public_columns.push(PublicColumn {
                col: terminal_col,
                values: terminal_prog,
            });
        }

        for (lane, acc_c) in [
            (0, layout.col_acc_value()),
            (1, layout.col_acc_owner_hi()),
            (2, layout.col_acc_owner_lo()),
        ] {
            constraints.push(Box::new(SelectorGate::new(
                terminal_col,
                Box::new(WeightedLinearGate::new(
                    vec![(acc_c, Block128::ONE)],
                    expected_batched_claims[lane],
                )),
            )));
        }

        // =====================================================================
        // 10. Delta-acc prefix-sum: same structure as gamma-acc
        //     delta_acc_lane[0] = eq_delta_lane[0] (row-0 pin)
        //     delta_acc_lane[i+1] = delta_acc_lane[i] + eq_delta_lane[i+1]
        // =====================================================================
        for (delta_acc_c, eq_delta_c) in [
            (layout.col_delta_acc_value(), layout.col_eq_delta_value()),
            (
                layout.col_delta_acc_owner_hi(),
                layout.col_eq_delta_owner_hi(),
            ),
            (
                layout.col_delta_acc_owner_lo(),
                layout.col_eq_delta_owner_lo(),
            ),
        ] {
            // Row-0: delta_acc[0] + eq_delta[0] == 0
            constraints.push(Box::new(SelectorGate::new(
                row0_col,
                Box::new(WeightedLinearGate::new_xor(vec![delta_acc_c, eq_delta_c])),
            )));

            // Shifted recurrence
            constraints.push(Box::new(SelectorGate::new(
                step_col,
                Box::new(WeightedLinearGateShifted::new(
                    vec![(delta_acc_c, Block128::ONE)],
                    vec![(delta_acc_c, Block128::ONE), (eq_delta_c, Block128::ONE)],
                    Block128::ZERO,
                )),
            )));
        }

        // Terminal: delta_acc_lane[n_slots-1] == prev_lane_openings[lane] + new_lane_openings[lane]
        // (in char-2, XOR is the net change between prev and new state evaluations at r)
        for (lane, delta_acc_c) in [
            (0, layout.col_delta_acc_value()),
            (1, layout.col_delta_acc_owner_hi()),
            (2, layout.col_delta_acc_owner_lo()),
        ] {
            let expected_delta = prev_lane_openings[lane] + new_lane_openings[lane];
            constraints.push(Box::new(SelectorGate::new(
                terminal_col,
                Box::new(WeightedLinearGate::new(
                    vec![(delta_acc_c, Block128::ONE)],
                    expected_delta,
                )),
            )));
        }

        // =====================================================================
        // Public columns: eval_point and gamma_powers
        // =====================================================================
        for k in 0..log_slots {
            let col = layout.col_eval_point(k);
            public_columns.push(PublicColumn {
                col,
                values: vec![eval_point[k]; n_rows],
            });
        }

        // gamma_powers: γ^0, γ^1, ..., γ^{n_rows-1}
        let mut gp_vals = vec![Block128::ONE; n_rows];
        for i in 1..n_rows {
            gp_vals[i] = gp_vals[i - 1] * gamma;
        }
        public_columns.push(PublicColumn {
            col: layout.col_gamma_powers(),
            values: gp_vals,
        });

        // =====================================================================
        // Boundary pins: claim triple values on live rows
        // =====================================================================
        for (r, claim) in claims.iter().enumerate() {
            let ind_col = layout.col_row_indicator(r);
            // Only emit indicators we haven't already pushed (row 0, terminal)
            if r != 0 && r != terminal_row {
                let prog = row_indicator_programme(r, n_rows);
                public_columns.push(PublicColumn {
                    col: ind_col,
                    values: prog,
                });
            }

            // Pin claim.value at row r
            constraints.push(Box::new(SelectorGate::new(
                ind_col,
                Box::new(WeightedLinearGate::new(
                    vec![(COL_VALUE, Block128::ONE)],
                    claim.value,
                )),
            )));
            // Pin claim.owner_hi at row r
            constraints.push(Box::new(SelectorGate::new(
                ind_col,
                Box::new(WeightedLinearGate::new(
                    vec![(COL_OWNER_HI, Block128::ONE)],
                    claim.owner_hi,
                )),
            )));
            // Pin claim.owner_lo at row r
            constraints.push(Box::new(SelectorGate::new(
                ind_col,
                Box::new(WeightedLinearGate::new(
                    vec![(COL_OWNER_LO, Block128::ONE)],
                    claim.owner_lo,
                )),
            )));

            // Pin idx bits at row r
            for b in 0..log_slots {
                let bit_val = Block128::from(((claim.slot_index >> b) & 1) as u128);
                constraints.push(Box::new(SelectorGate::new(
                    ind_col,
                    Box::new(WeightedLinearGate::new(
                        vec![(layout.col_idx_bit(b), Block128::ONE)],
                        bit_val,
                    )),
                )));
            }

            // Pin is_spend, is_mint at row r
            constraints.push(Box::new(SelectorGate::new(
                ind_col,
                Box::new(WeightedLinearGate::new(
                    vec![(layout.col_is_spend(), Block128::ONE)],
                    Block128::from(claim.is_spend as u128),
                )),
            )));
            constraints.push(Box::new(SelectorGate::new(
                ind_col,
                Box::new(WeightedLinearGate::new(
                    vec![(layout.col_is_mint(), Block128::ONE)],
                    Block128::from(claim.is_mint as u128),
                )),
            )));
        }

        // Remaining row indicators for rows that had no claims (padding rows)
        for r in claims.len()..n_rows {
            if r != 0 && r != terminal_row {
                let ind_col = layout.col_row_indicator(r);
                let prog = row_indicator_programme(r, n_rows);
                public_columns.push(PublicColumn {
                    col: ind_col,
                    values: prog,
                });
            }
        }

        Self {
            layout,
            n_cols,
            constraints,
            public_columns,
            eval_point: eval_point.to_vec(),
            prev_lane_openings,
            new_lane_openings,
        }
    }

    pub fn layout(&self) -> BlockStateBindingLayout {
        self.layout
    }

    pub fn into_parts(self) -> (usize, Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
        (self.n_cols, self.constraints, self.public_columns)
    }

    /// Build the full trace from a witness, overlaying public columns.
    pub fn build_trace(&self, witness: &BlockStateBindingWitness) -> Vec<Vec<Block128>> {
        let mut cols = witness.build_columns();
        for pc in &self.public_columns {
            cols[pc.col] = pc.values.clone();
        }
        cols
    }

    /// Extend trace columns from `n_rows` to `2^target_log` for the interleaved commitment.
    ///
    /// Standard zero-padding violates the eq-ladder base constraint at external rows:
    ///   `eq_0 + r_0 + b_0 + 1 = 0 + 0 + 0 + 1 = 1 ≠ 0`  (char-2)
    ///
    /// Fix: pad eq_ladder columns with `1` at external rows.
    /// With `r_k = 0` (zero-padded) and `b_k = 0` at those rows:
    ///   - Base:  `1 + 0 + 0 + 1 = 0` ✓
    ///   - Step:  `eq_k + eq_{k-1} * (1+0+0) = 1 + 1 = 0` ✓  (char-2)
    /// All other columns remain zero-padded (selectors gate every other constraint).
    ///
    /// Does not allocate if `target_log <= self.log_rows()`.
    pub fn extend_for_proving(
        &self,
        cols: Vec<Vec<Block128>>,
        target_log: usize,
    ) -> Vec<Vec<Block128>> {
        let n_rows = self.layout.n_rows();
        let target = 1usize << target_log;
        if target <= n_rows {
            return cols;
        }
        // eq_ladder columns occupy a contiguous range.
        let eq_base = self.layout.col_eq_ladder(0);
        let eq_end = eq_base + self.layout.log_slots; // exclusive
        cols.into_iter()
            .enumerate()
            .map(|(idx, mut col)| {
                let pad = if idx >= eq_base && idx < eq_end {
                    Block128::ONE
                } else {
                    Block128::ZERO
                };
                col.resize(target, pad);
                col
            })
            .collect()
    }
}

impl Air for BlockStateBindingAir {
    fn n_columns(&self) -> usize {
        self.n_cols
    }

    fn log_rows(&self) -> usize {
        self.layout.log_rows
    }

    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }

    fn public_columns(&self) -> &[PublicColumn] {
        &self.public_columns
    }
}

// =============================================================================
// Helpers
// =============================================================================

const fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut k = 0;
    let mut v = n - 1;
    while v > 0 {
        v >>= 1;
        k += 1;
    }
    k
}

// =============================================================================
// Exported column accessors (for external consumers)
// =============================================================================

pub fn col_value() -> usize {
    COL_VALUE
}
pub fn col_owner_hi() -> usize {
    COL_OWNER_HI
}
pub fn col_owner_lo() -> usize {
    COL_OWNER_LO
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Trace;

    const LOG_SLOTS: usize = 4;

    fn mk_spend(seed: u128, slot: u32) -> BlockStateBindingClaim {
        let val = Block128::from(seed * 0x1111);
        let hi = Block128::from(seed * 0x2222);
        let lo = Block128::from(seed * 0x3333);
        BlockStateBindingClaim::spend(slot, val, hi, lo)
    }

    fn mk_mint(seed: u128, slot: u32) -> BlockStateBindingClaim {
        let val = Block128::from(seed * 0x4444);
        let hi = Block128::from(seed * 0x5555);
        let lo = Block128::from(seed * 0x6666);
        BlockStateBindingClaim::mint(slot, val, hi, lo)
    }

    fn mk_eval_point() -> Vec<Block128> {
        (0..LOG_SLOTS)
            .map(|i| Block128::from(0x100u128 + (i as u128) * 0x11))
            .collect()
    }

    fn mk_gamma() -> Block128 {
        Block128::from(0xB16B_00B5_0000_BEEFu128)
    }

    fn mk_prev_lane_openings() -> [Block128; 3] {
        [
            Block128::from(0xA5A5_1234_5678_9ABCu128),
            Block128::from(0xDEAD_BEEF_CAFE_F00Du128),
            Block128::from(0x1357_9BDF_2468_ACE0u128),
        ]
    }

    fn mk_claims_single_tx() -> Vec<BlockStateBindingClaim> {
        vec![
            mk_spend(11, 0),
            mk_spend(22, 3),
            mk_mint(33, 5),
            mk_mint(44, 9),
        ]
    }

    fn mk_claims_multi_tx() -> Vec<BlockStateBindingClaim> {
        vec![
            // Tx 0: 2 spends + 2 mints
            mk_spend(1, 0),
            mk_spend(2, 3),
            mk_mint(3, 5),
            mk_mint(4, 7),
            // Tx 1: 1 spend + 1 mint
            mk_spend(5, 10),
            mk_mint(6, 12),
            // Padding
            BlockStateBindingClaim::EMPTY,
            BlockStateBindingClaim::EMPTY,
        ]
    }

    fn mk_witness(claims: Vec<BlockStateBindingClaim>) -> BlockStateBindingWitness {
        let eval_point = mk_eval_point();
        let gamma = mk_gamma();
        let prev = mk_prev_lane_openings();

        let mut w = BlockStateBindingWitness::new(
            claims,
            eval_point,
            gamma,
            prev,
            [Block128::ZERO; 3], // placeholder
        );
        let new = w.expected_new_lane_openings(prev);
        w.new_lane_openings = new;
        w
    }

    fn mk_air(
        claims: &[BlockStateBindingClaim],
        witness: &BlockStateBindingWitness,
    ) -> BlockStateBindingAir {
        let expected_batched = witness.expected_batched_claims();
        BlockStateBindingAir::new(
            claims,
            witness.prev_lane_openings,
            witness.new_lane_openings,
            &witness.eval_point,
            witness.gamma,
            expected_batched,
        )
    }

    // =================================================================
    // Happy path
    // =================================================================

    #[test]
    fn honest_single_tx_trace_passes() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let cols = air.build_trace(&witness);
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn honest_multi_tx_trace_passes() {
        let claims = mk_claims_multi_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let cols = air.build_trace(&witness);
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn all_mints_trace_passes() {
        let claims = vec![mk_mint(1, 0), mk_mint(2, 5), mk_mint(3, 10), mk_mint(4, 15)];
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let cols = air.build_trace(&witness);
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn all_spends_trace_passes() {
        let claims = vec![
            mk_spend(1, 0),
            mk_spend(2, 5),
            mk_spend(3, 10),
            mk_spend(4, 15),
        ];
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let cols = air.build_trace(&witness);
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn minimal_two_slot_trace_passes() {
        let claims = vec![mk_spend(1, 0), mk_mint(2, 1)];
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let cols = air.build_trace(&witness);
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    // =================================================================
    // Tamper detection — claim boundary pins
    // =================================================================

    #[test]
    fn tampered_value_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let mut cols = air.build_trace(&witness);
        cols[COL_VALUE][0] += Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_owner_hi_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let mut cols = air.build_trace(&witness);
        cols[COL_OWNER_HI][1] += Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_slot_index_bit_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let mut cols = air.build_trace(&witness);
        cols[COL_IDX_BIT_BASE][0] = Block128::from(2u128);
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    // =================================================================
    // Tamper detection — boolean gates
    // =================================================================

    #[test]
    fn live_mask_non_bool_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        cols[layout.col_live_mask()][0] = Block128::from(2u128);
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn is_spend_non_bool_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        cols[layout.col_is_spend()][0] = Block128::from(2u128);
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn is_mint_non_bool_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        cols[layout.col_is_mint()][0] = Block128::from(2u128);
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    // =================================================================
    // Tamper detection — action exclusivity and union
    // =================================================================

    #[test]
    fn is_spend_and_is_mint_both_set_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        // Row 0 is spend. Force is_mint=1 and live_mask=0 to bypass union.
        cols[layout.col_is_mint()][0] = Block128::ONE;
        cols[layout.col_live_mask()][0] = Block128::ZERO;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn live_mask_out_of_sync_with_actions_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        // Padding row: is_spend=0, is_mint=0, but live_mask=1.
        let pad_row = claims.len(); // first padding row
        if pad_row < layout.n_rows() {
            cols[layout.col_live_mask()][pad_row] = Block128::ONE;
            let trace = Trace::new(cols);
            assert!(!air.check(&trace));
        }
    }

    // =================================================================
    // Tamper detection — delta identity
    // =================================================================

    #[test]
    fn live_row_wrong_delta_value_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        cols[layout.col_delta_value()][0] += Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn non_live_row_tolerates_nonzero_delta() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        // Padding row: delta is unconstrained (live_mask=0 silences).
        let pad_row = claims.len();
        if pad_row < layout.n_rows() {
            cols[layout.col_delta_value()][pad_row] = Block128::from(0xFFu128);
            let trace = Trace::new(cols);
            assert!(air.check(&trace));
        }
    }

    // =================================================================
    // Tamper detection — pre-state source
    // =================================================================

    #[test]
    fn opened_pre_equals_claim_on_spend_row() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let cols = air.build_trace(&witness);
        // Row 0 is spend: opened_pre_value = claim.value
        assert_eq!(cols[layout.col_opened_pre_value()][0], cols[COL_VALUE][0]);
        assert_eq!(
            cols[layout.col_opened_pre_owner_hi()][0],
            cols[COL_OWNER_HI][0]
        );
    }

    #[test]
    fn opened_pre_is_zero_on_mint_row() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let cols = air.build_trace(&witness);
        // Row 2 is mint: opened_pre must be zero (is_spend=0)
        assert_eq!(cols[layout.col_opened_pre_value()][2], Block128::ZERO);
        assert_eq!(cols[layout.col_opened_pre_owner_hi()][2], Block128::ZERO);
        assert_eq!(cols[layout.col_opened_pre_owner_lo()][2], Block128::ZERO);
    }

    #[test]
    fn tampered_opened_pre_on_spend_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        cols[layout.col_opened_pre_value()][0] += Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    // =================================================================
    // Tamper detection — gamma-RLC closure
    // =================================================================

    #[test]
    fn expected_batched_claims_matches_trace_terminal() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let cols = air.build_trace(&witness);
        let expected = witness.expected_batched_claims();
        let term = layout.n_slots.saturating_sub(1);
        assert_eq!(cols[layout.col_acc_value()][term], expected[0]);
        assert_eq!(cols[layout.col_acc_owner_hi()][term], expected[1]);
        assert_eq!(cols[layout.col_acc_owner_lo()][term], expected[2]);
    }

    #[test]
    fn tampered_gamma_acc_terminal_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        let term = layout.n_slots.saturating_sub(1);
        cols[layout.col_acc_value()][term] += Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    // =================================================================
    // Tamper detection — delta-acc closure (state root binding)
    // =================================================================

    #[test]
    fn expected_new_lane_openings_matches_witness() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let expected = witness.expected_new_lane_openings(witness.prev_lane_openings);
        assert_eq!(expected, witness.new_lane_openings);
    }

    #[test]
    fn tampered_delta_acc_terminal_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        let term = layout.n_slots.saturating_sub(1);
        cols[layout.col_delta_acc_value()][term] += Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    // =================================================================
    // Tamper detection — eq-ladder
    // =================================================================

    #[test]
    fn tampered_eq_ladder_rejects() {
        let claims = mk_claims_single_tx();
        let witness = mk_witness(claims.clone());
        let air = mk_air(&claims, &witness);
        let layout = witness.layout;
        let mut cols = air.build_trace(&witness);
        cols[layout.col_eq_ladder(0)][0] += Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    // =================================================================
    // Layout consistency
    // =================================================================

    #[test]
    fn layout_column_count_is_consistent() {
        let layout = BlockStateBindingLayout {
            n_slots: 4,
            log_rows: 3,
            log_slots: 4,
        };
        let n_cols = layout.n_cols();
        // All column accessors must be < n_cols
        assert!(layout.col_acc_step_indicator() < n_cols);
        // Last column is acc_step_indicator
        assert_eq!(layout.col_acc_step_indicator(), n_cols - 1);
    }

    #[test]
    fn columns_are_pairwise_distinct() {
        let layout = BlockStateBindingLayout {
            n_slots: 4,
            log_rows: 3,
            log_slots: 4,
        };
        let cols = vec![
            COL_VALUE,
            COL_OWNER_HI,
            COL_OWNER_LO,
            layout.col_idx_bit(0),
            layout.col_idx_bit(3),
            layout.col_delta_value(),
            layout.col_live_mask(),
            layout.col_is_spend(),
            layout.col_is_mint(),
            layout.col_opened_pre_value(),
            layout.col_eq_delta_value(),
            layout.col_delta_acc_value(),
            layout.col_eval_point(0),
            layout.col_eq_ladder(0),
            layout.col_gamma_powers(),
            layout.col_gp_value(),
            layout.col_acc_value(),
            layout.col_row_indicator(0),
            layout.col_acc_step_indicator(),
        ];
        for i in 0..cols.len() {
            for j in (i + 1)..cols.len() {
                assert_ne!(
                    cols[i], cols[j],
                    "Columns {} and {} collide at index {}",
                    i, j, cols[i]
                );
            }
        }
    }
}
