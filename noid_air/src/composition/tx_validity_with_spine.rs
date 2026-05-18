// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Spine-embedded tx-validity composite with a verbatim leaf-band.
//!
//! Constructs a [`crate::CompositeAir`] at `outer_log_rows = 13` that
//! embeds:
//! - the full
//!   [`super::tx_validity_leaf::TxValidityCompositeLeaf`] verbatim at
//!   outer columns `[0, TX_VALIDITY_LEAF_N_COLS)`; the leaf's T2a bridge
//!   is retargeted at the spine's `TxValidityCol::AuthTagHi/Lo` cells.
//! - the [`crate::airs::tx_body_spine::TxBodySpineComposite`] block
//!   immediately past the leaf-band, shifted by
//!   [`SPINE_BLOCK_OUTER_BASE`] via [`ShiftedColumnsConstraint`].

use crate::airs::fri_state_combiner_composite::FriStateCombinerComposite;
use crate::airs::fri_state_open::{FriStateOpenAir, FriStateOpenWitness, FRI_STATE_OPEN_N_INPUTS};
use crate::airs::tx_body_merkle::{TxBodyMerkleBoundaryPins, TXBODY_MERKLE_N_PERMS};
use crate::airs::tx_body_spine::{spine_n_cols, TxBodySpineComposite, SPINE_LOG_ROWS};
use crate::composition::spine_adapter::SpineEmbeddingLayout;
use crate::composition::tx_validity_leaf::{
    write_leaf_block_traces, LeafConstructionOptions, TxValidityCompositeLeaf,
    SKEL_IS_COINBASE_COL, TX_VALIDITY_LEAF_LOG_ROWS, TX_VALIDITY_LEAF_N_COLS,
};
use crate::gates::const_column::PublicColumn;
use crate::gates::selector::SelectorGate;
use crate::{Air, CompositeAir, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::{Block128, TowerField};
use noid_tx::TxBody;

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Outer log-rows. The spine demands `≥ SPINE_LOG_ROWS = 13` and the
/// leaf composite is fixed at `13`; they coincide.
pub const TX_VALIDITY_WITH_SPINE_LOG_ROWS: usize = SPINE_LOG_ROWS;

/// Width reserved for the embedded leaf-band — exactly matches the
/// leaf composite's column count.
pub const LEAF_BAND_RESERVED: usize = TX_VALIDITY_LEAF_N_COLS;

const _: () = {
    assert!(TX_VALIDITY_WITH_SPINE_LOG_ROWS == SPINE_LOG_ROWS);
    assert!(TX_VALIDITY_WITH_SPINE_LOG_ROWS == TX_VALIDITY_LEAF_LOG_ROWS);
};

/// Outer column at which the embedded spine block begins.
pub const SPINE_BLOCK_OUTER_BASE: usize = LEAF_BAND_RESERVED;

/// E.5.f₄ — outer column index reserved for the coinbase-credit bit
/// programme. On every row it carries bit `r mod 128` of
/// `coinbase_credit` when `r < 64` (instance-0 band), zero elsewhere.
/// Pinned via `PublicColumn`, tied to `B21.sum` on coinbase by the
/// f₄ equality gate, and forced to zero on regular txs by
/// `(1 + is_coinbase) · credit_bit == 0`.
pub fn coinbase_credit_bit_col() -> usize {
    SPINE_BLOCK_OUTER_BASE + spine_n_cols()
}

/// Total outer column count.
pub fn tx_validity_with_spine_n_cols() -> usize {
    coinbase_credit_bit_col() + 1
}

// ---------------------------------------------------------------------------
// Column-shift adapter (mirrors the per-composite adapter pattern used
// elsewhere). Used only for the spine block; the leaf-band is embedded
// at outer offset 0 and its constraints carry over without any column
// shift.
// ---------------------------------------------------------------------------

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
                "constraint col {c} >= inner range {inner_n_cols}"
            );
        }
        for &c in inner.shifted_columns() {
            assert!(
                c < inner_n_cols,
                "constraint shifted col {c} >= inner range {inner_n_cols}"
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

// ---------------------------------------------------------------------------
// Composite
// ---------------------------------------------------------------------------

/// Spine-embedded composite: full leaf composite (verbatim) +
/// `TxBodySpineComposite` block. The leaf's T2a bridge is retargeted at
/// the spine's `TxValidityCol::AuthTagHi/Lo` cells.
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
    /// E.2.b.comp-3: output-side witness source used at construction.
    /// Mirrored into `build_trace` so the embedded leaf-band honest
    /// sub-trace matches the constraints emitted by the composite AIR.
    output_side: crate::composition::tx_validity_composite::OutputSideSource,
    /// E.5.d: tx-level coinbase marker threaded into the embedded
    /// leaf-band and into the WithSpine-level `is_coinbase · fee = 0`
    /// tie. Mirrored here so `build_trace` can assert the wiring
    /// invariant `is_coinbase ⇒ balance_fee == 0` (data-safety sanity).
    is_coinbase: bool,
    /// E.5.f₄ — declared coinbase mint. Equal to `Σ outputs` on a
    /// well-formed coinbase tx; zero on regular txs. Surfaced through
    /// `public_inputs()` and pinned into the `credit_bit_col` programme.
    coinbase_credit: u64,
}

/// E.5.d / E.5.f₄ — optional construction tweaks for
/// [`TxValidityCompositeWithSpine`]. `Default` reproduces the canonical
/// non-coinbase wiring.
#[derive(Debug, Clone, Copy, Default)]
pub struct WithSpineOptions {
    /// Tx-level coinbase flag. When `true`, the embedded leaf enforces
    /// `n_inputs = 0` (see `tx_validity_leaf.rs`) and WithSpine adds
    /// `is_coinbase · fee_bit == 0` across all 64 bit-rows of the
    /// balance `B21.b` (fee) column. Caller must supply
    /// `balance_fee = 0` when `is_coinbase = true` — the constructor
    /// asserts this to catch wiring mistakes early.
    pub is_coinbase: bool,
    /// E.5.f₄ — coinbase minted amount. When `is_coinbase = true`, the
    /// sum of all outputs must equal this u64. Pinned into the verifier
    /// surface via `PublicInputs.coinbase_credit` and enforced in-circuit
    /// by a `PublicColumn` on `B21.sum` carrying the 64 bits of
    /// `coinbase_credit`. Must be `0` when `is_coinbase = false` — the
    /// constructor asserts this.
    pub coinbase_credit: u64,
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
    ) -> Self {
        Self::new_with_options(
            boundary_pins,
            body,
            balance_inputs,
            balance_outputs,
            balance_fee,
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            WithSpineOptions::default(),
        )
    }

    /// E.5.d — construct with caller-supplied [`WithSpineOptions`].
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        boundary_pins: TxBodyMerkleBoundaryPins,
        body: TxBody,
        balance_inputs: [u64; 4],
        balance_outputs: [u64; 8],
        balance_fee: u64,
        merkle_inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        options: WithSpineOptions,
    ) -> Self {
        if options.is_coinbase {
            assert_eq!(
                balance_fee, 0,
                "Stage E.5.d: is_coinbase = true requires balance_fee == 0",
            );
            // E.5.f₄: `Σ outputs == coinbase_credit` on a well-formed
            // coinbase tx. Asserted here (before any AIR is built) so
            // callers get an immediate data-safety warning; the
            // in-circuit `CreditEqualsB21SumGate` enforces the same
            // binding against the B-chain tail.
            let sum_out: u128 = balance_outputs.iter().map(|&x| x as u128).sum();
            assert_eq!(
                sum_out, options.coinbase_credit as u128,
                "Stage E.5.f₄: Σ outputs must equal coinbase_credit on coinbase tx",
            );
        } else {
            assert_eq!(
                options.coinbase_credit, 0,
                "Stage E.5.f₄: coinbase_credit must be 0 when is_coinbase = false",
            );
        }
        let outer_n_cols = tx_validity_with_spine_n_cols();
        let outer_log_rows = TX_VALIDITY_WITH_SPINE_LOG_ROWS;

        let spine_layout =
            SpineEmbeddingLayout::new(SPINE_BLOCK_OUTER_BASE, outer_n_cols, outer_log_rows)
                .expect("spine layout must fit by construction");

        // The spine's `AuthTagHi/Lo[i]` cells are bound solely by the
        // spine's own MAC gate against the external AuthGKR pins.

        // Build the leaf composite and consume it for its constraints /
        // publics + witness pieces required to rebuild the leaf-band
        // sub-trace.
        // E.2.b.comp-3: thread the body's outputs into the leaf's
        // output-side `FriStateOpenAir` block as mint claims. The
        // spine block already owns `self.body`, so every live
        // `TxOutput` becomes a mint claim carrying its declared
        // `slot_index`, `value` and owner lanes; inactive outputs stay
        // `FriStateOpenClaim::EMPTY`. `prev_lane_openings` are the
        // verifier-known FRI openings of `prev_state` at the
        // output-side eval point — wired to zero here (honest
        // shape-only path; Stage 6 PublicInputs will lift them into
        // the verifier surface).
        let output_side = crate::composition::tx_validity_composite::OutputSideSource::FromBody {
            outputs: body.outputs.clone(),
            prev_lane_openings: [Block128::ZERO; 3],
        };
        let leaf = TxValidityCompositeLeaf::new_with_options(
            combiner,
            open_air,
            open_witness,
            LeafConstructionOptions {
                output_side: output_side.clone(),
                is_coinbase: options.is_coinbase,
                ..LeafConstructionOptions::default()
            },
        );
        let (leaf_air, combiner, open_witness, open_public_columns) = leaf.into_parts();
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
        //
        // E.5.f₄ — cross-chain equality mux. The only balance constraints
        // that encode UTXO conservation (`Σ inputs ≡ Σ outputs + fee`)
        // are the two A2↔B21 final-equality gates. They touch columns in
        // both the `A2` and `B21` `bit_adder` blocks and are wrapped in
        // `SelectorGate::new_negated(SKEL_IS_COINBASE_COL, …)` so the
        // identity is silenced on coinbase txs (replaced by
        // `B21 ≡ coinbase_credit` emitted below). Every other balance
        // constraint — per-block `bit_adder` internals, inter-block
        // bridges, and the B-chain integer overflow gates — stays active
        // on coinbase so the prover cannot use a silent chain wrap as an
        // escape hatch.
        let block_base = spine_layout.block_base();
        let balance_outer_lo = {
            use crate::airs::tx_body_spine::TXV_COL_OFFSET;
            use crate::airs::tx_validity::TX_VALIDITY_BALANCE_COL_OFFSET;
            block_base + TXV_COL_OFFSET + TX_VALIDITY_BALANCE_COL_OFFSET
        };
        let a2_block_lo = {
            use crate::airs::bit_adder::BIT_ADDER_N_COLS;
            balance_outer_lo + 2 * BIT_ADDER_N_COLS
        };
        let a2_block_hi = {
            use crate::airs::bit_adder::BIT_ADDER_N_COLS;
            a2_block_lo + BIT_ADDER_N_COLS
        };
        let b21_block_lo = {
            use crate::airs::balance_gate::BALANCE_BLK_B21;
            use crate::airs::bit_adder::BIT_ADDER_N_COLS;
            balance_outer_lo + BALANCE_BLK_B21 * BIT_ADDER_N_COLS
        };
        let b21_block_hi = {
            use crate::airs::bit_adder::BIT_ADDER_N_COLS;
            b21_block_lo + BIT_ADDER_N_COLS
        };
        for c in spine_constraints {
            let shifted = ShiftedColumnsConstraint::new(c, block_base, spine_n);
            let touches_a2 = shifted
                .columns()
                .iter()
                .chain(shifted.shifted_columns().iter())
                .any(|&col| col >= a2_block_lo && col < a2_block_hi);
            let touches_b21 = shifted
                .columns()
                .iter()
                .chain(shifted.shifted_columns().iter())
                .any(|&col| col >= b21_block_lo && col < b21_block_hi);
            if touches_a2 && touches_b21 {
                constraints.push(Box::new(SelectorGate::new_negated(
                    SKEL_IS_COINBASE_COL,
                    Box::new(shifted),
                )));
            } else {
                constraints.push(Box::new(shifted));
            }
        }
        for pc in spine_publics {
            assert!(pc.col < spine_n);
            public_columns.push(PublicColumn::new(pc.col + block_base, pc.values));
        }

        // E.5.d.2 — `is_coinbase · fee_bit == 0` on every row.
        //
        // `fee_bit_col` is the `B21.b` bit-column of the balance block
        // embedded inside the spine. Its programme (pinned via
        // `emit_balance_value_public_columns` at Stage 3d-0.10.5) carries
        // bit `r` of `balance_fee` on rows `[0, 64)` of instance 0 and
        // zero everywhere else. With `is_coinbase` also pinned as a
        // row-constant public column on the leaf side, the identity
        //     is_coinbase · fee_bit == 0
        // holds iff `is_coinbase = 0` (any fee permitted) or every bit
        // of `balance_fee` is zero (i.e. `balance_fee == 0`). Degree 2,
        // no row gating needed.
        {
            use crate::airs::balance_gate::BALANCE_N_BLOCKS;
            use crate::airs::bit_adder::{BIT_ADDER_COL_B, BIT_ADDER_N_COLS};
            use crate::airs::tx_body_spine::TXV_COL_OFFSET;
            use crate::airs::tx_validity::TX_VALIDITY_BALANCE_COL_OFFSET;
            // `B21` is balance block ordinal 10 — the last block. Derive
            // via `BALANCE_N_BLOCKS - 1` to keep this pin free of the
            // private `BLK_B21` constant.
            const BLK_B21: usize = BALANCE_N_BLOCKS - 1;
            let fee_bit_col = block_base
                + TXV_COL_OFFSET
                + TX_VALIDITY_BALANCE_COL_OFFSET
                + BLK_B21 * BIT_ADDER_N_COLS
                + BIT_ADDER_COL_B;

            struct CoinbaseNoFeeGate {
                cols: [usize; 2],
            }
            impl Constraint for CoinbaseNoFeeGate {
                fn degree(&self) -> usize {
                    2
                }
                fn columns(&self) -> &[usize] {
                    &self.cols
                }
                fn evaluate(&self, frame: EvalFrame) -> Block128 {
                    frame.local[0] * frame.local[1]
                }
                fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
                    noid_core::hardware::clmul_gcm(frame.local[0], frame.local[1])
                }
            }
            constraints.push(Box::new(CoinbaseNoFeeGate {
                cols: [SKEL_IS_COINBASE_COL, fee_bit_col],
            }));
        }

        // E.5.f₃ — SKEL_IS_COINBASE_COL ↔ tx-body L14 bridge.
        //
        // Under the AIR-spine path: the native `hash_tx_body` encodes
        // `is_coinbase` into leaf 14 as `[is_coinbase as u128, 0]`, and
        // `TxBodyMerkleAir` pins that word onto `pre_s[0]` at
        // instance-42 row-0 via O3.b (`pins.is_coinbase_leaf[0]`).
        // Independently, the leaf band exposes the scalar `is_coinbase`
        // on every row of `SKEL_IS_COINBASE_COL` (Stage E.5.d). The
        // inner gate below ties the two sources so a prover cannot
        // publish inconsistent `is_coinbase` values to the spine-side
        // mux and to the tx-body-hash L14 leaf: at the single hot row
        // where the Merkle pin indicator `pin_base + 1` is ONE, force
        //     pre_s[0] + SKEL_IS_COINBASE_COL == 0
        // (addition is XOR over GF(2^128); for {0, 1} scalars this is
        // equality). Everywhere else the gate is silenced by the
        // single-hot indicator.
        //
        // # G4.a — merkle-interior cell retired
        //
        // The historical inner gate read `pre_s[0]` at instance-42
        // row-0. That cell no longer exists — GKR owns the 59-perm
        // block — so the inner gate is retired.
        //
        // Soundness is preserved without replacement:
        //
        //   1. The GKR spine absorbs `SpineInputs.is_coinbase_leaf` into
        //      its wrap computation, producing `tx_body_hash`.
        //   2. The wrap output is pinned at
        //      `boundary_pins.tx_body_hash` — the same cell the STARK
        //      sees via `TxBodyMerkleBoundaryAir`'s row-wide
        //      `PublicColumn`.
        //   3. The construction-time asserts below force
        //      `boundary_pins.is_coinbase_leaf == [is_coinbase as u128, 0]`
        //      and `body.is_coinbase == options.is_coinbase`, so the
        //      public-input surface is consistent.
        //   4. If the prover supplies a `SpineInputs` whose
        //      `is_coinbase_leaf` disagrees with `SKEL_IS_COINBASE_COL`,
        //      the GKR-produced `tx_body_hash` disagrees with the leaf-
        //      pinned one, and the shared `tx_body_hash` pin fails.
        //
        // Net: the merkle-interior tie is redundant once GKR owns the
        // L14 absorb. The asserts stay — they're cheap, catch config
        // drift at construction time, and are not part of the proof.
        {
            assert_eq!(
                body.is_coinbase, options.is_coinbase,
                "Stage E.5.f₃: body.is_coinbase must agree with options.is_coinbase",
            );
            let declared_word = Block128::from(options.is_coinbase as u128);
            assert_eq!(
                boundary_pins.is_coinbase_leaf[0], declared_word,
                "Stage E.5.f₃: boundary_pins.is_coinbase_leaf[0] must equal is_coinbase",
            );
            assert_eq!(
                boundary_pins.is_coinbase_leaf[1],
                Block128::ZERO,
                "Stage E.5.f₃: boundary_pins.is_coinbase_leaf[1] must be zero (native L14 shape)",
            );

            // E.5.f₃ merkle-interior gate (pre_s[0] + SKEL_IS_COINBASE_COL
            // at instance-42) is retired — GKR owns the 59-perm
            // soundness and the merkle band no longer carries the
            // pre_s / pin-ind cells.
        }

        // E.5.f₄ — coinbase-credit bit programme + equality gates.
        //
        // A single dedicated outer column `credit_bit_col` holds the
        // 64-bit decomposition of `options.coinbase_credit`: bit `r` on
        // row `r` for `r ∈ 0..64` of instance 0, zero everywhere else.
        // Pinned via `PublicColumn` so its contents are part of the
        // verifier-visible public data.
        //
        // Two degree-2 constraints close the mux:
        //
        // 1. `(1 + is_coinbase) · credit_bit == 0` on every row.
        //    Forces `coinbase_credit == 0` on regular txs — the only
        //    value a `PublicInputs.coinbase_credit` can carry consistent
        //    with the witness is zero.
        //
        // 2. `is_coinbase · is_input_B21 · (B21.sum + credit_bit) == 0`
        //    on every row. On coinbase txs, equates the low 67 bits of
        //    `B21.sum` (active rows of the B21 bit-adder) with
        //    `credit_bit`. Since the programme zeroes all bits beyond
        //    bit 63, this forces sum-bits 64..66 to zero too, tying
        //    `Σ outputs + fee == coinbase_credit` at the bit level.
        //    Combined with the existing `is_coinbase · fee_bit == 0`
        //    gate (which pins `fee == 0` on coinbase), the identity
        //    reduces to `Σ outputs == coinbase_credit`.
        //
        // Silent-wrap escape is blocked because the B-chain overflow
        // gates (`BalanceZeroAtTransitionGate` on `B21.sum[66]` and
        // `B21.carry[67]`) stay active on coinbase: the mux at the top
        // of this function only silences the two cross-chain equality
        // gates, not the overflow guards.
        {
            use crate::airs::balance_gate::BALANCE_BLK_B21;
            use crate::airs::bit_adder::{
                bit_adder_operand_programme, BIT_ADDER_COL_IS_INPUT, BIT_ADDER_COL_SUM,
                BIT_ADDER_N_COLS,
            };
            use crate::airs::tx_body_spine::TXV_COL_OFFSET;
            use crate::airs::tx_validity::TX_VALIDITY_BALANCE_COL_OFFSET;

            let credit_bit_col = coinbase_credit_bit_col();
            let b21_block_base = block_base
                + TXV_COL_OFFSET
                + TX_VALIDITY_BALANCE_COL_OFFSET
                + BALANCE_BLK_B21 * BIT_ADDER_N_COLS;
            let b21_sum_col = b21_block_base + BIT_ADDER_COL_SUM;
            let b21_is_input_col = b21_block_base + BIT_ADDER_COL_IS_INPUT;

            // Pin the 64-bit credit programme.
            public_columns.push(PublicColumn::new(
                credit_bit_col,
                bit_adder_operand_programme(64, options.coinbase_credit, outer_log_rows),
            ));

            // Gate 1: (1 + is_coinbase) · credit_bit == 0.
            struct CreditZeroOnRegularGate {
                cols: [usize; 2],
            }
            impl Constraint for CreditZeroOnRegularGate {
                fn degree(&self) -> usize {
                    2
                }
                fn columns(&self) -> &[usize] {
                    &self.cols
                }
                fn evaluate(&self, frame: EvalFrame) -> Block128 {
                    (Block128::ONE + frame.local[0]) * frame.local[1]
                }
                fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
                    noid_core::hardware::clmul_gcm(frame.local[0] ^ 1u128, frame.local[1])
                }
            }
            constraints.push(Box::new(CreditZeroOnRegularGate {
                cols: [SKEL_IS_COINBASE_COL, credit_bit_col],
            }));

            // Gate 2: is_coinbase · is_input_B21 · (B21.sum + credit_bit) == 0.
            struct CreditEqualsB21SumGate {
                cols: [usize; 4],
            }
            impl Constraint for CreditEqualsB21SumGate {
                fn degree(&self) -> usize {
                    3
                }
                fn columns(&self) -> &[usize] {
                    &self.cols
                }
                fn evaluate(&self, frame: EvalFrame) -> Block128 {
                    let is_coinbase = frame.local[0];
                    let is_input_b21 = frame.local[1];
                    let b21_sum = frame.local[2];
                    let credit_bit = frame.local[3];
                    is_coinbase * is_input_b21 * (b21_sum + credit_bit)
                }
                fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
                    use noid_core::hardware::clmul_gcm;
                    let t = frame.local[2] ^ frame.local[3];
                    clmul_gcm(frame.local[0], clmul_gcm(frame.local[1], t))
                }
            }
            constraints.push(Box::new(CreditEqualsB21SumGate {
                cols: [
                    SKEL_IS_COINBASE_COL,
                    b21_is_input_col,
                    b21_sum_col,
                    credit_bit_col,
                ],
            }));
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
            output_side,
            is_coinbase: options.is_coinbase,
            coinbase_credit: options.coinbase_credit,
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
            outer_n_cols,
            TX_VALIDITY_WITH_SPINE_LOG_ROWS,
            &self.output_side,
            self.open_witness.eval_point,
            self.open_witness.gamma,
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

    /// E.5.d: mirror of the tx-level coinbase flag this composite was
    /// constructed with. Consumed by f₃ (SKEL_IS_COINBASE_COL bridge)
    /// and by debug asserts in `build_trace`.
    pub fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }

    /// Stage 6 — tx body hash the trace was built with.
    pub fn tx_body_hash_fields(&self) -> [Block128; 2] {
        self.boundary_pins.tx_body_hash
    }

    /// Stage 6 — declared fee the balance block was pinned to.
    pub fn balance_fee(&self) -> u64 {
        self.balance_fee
    }

    /// Stage 6 — expected `prev_state_root` as pinned into the
    /// combiner's prev-side.
    pub fn expected_prev_state_root_fields(&self) -> [Block128; 2] {
        self.combiner.expected_prev_state_root_fields()
    }

    /// Stage 6 — expected `new_state_root` as pinned into the
    /// combiner's new-side.
    pub fn expected_new_state_root_fields(&self) -> [Block128; 2] {
        self.combiner.expected_new_state_root_fields()
    }

    /// Stage 6 — derive the canonical `PublicInputs` from the four
    /// scalars already pinned into the composite's sub-AIRs. Each
    /// scalar is read from its single source of truth; no fresh
    /// pins introduced.
    ///
    /// - `prev_state_root` ← combiner prev-side expected digest.
    /// - `new_state_root`  ← combiner new-side expected digest.
    /// - `tx_body_hash`    ← `boundary_pins.tx_body_hash` (Stage 1 O2 tie).
    /// - `fee`             ← `balance_fee` pinned via `emit_balance_value_public_columns`.
    ///
    /// The returned `PublicInputs` is the **only** verifier-visible
    /// surface (Stage 6 (b)).
    pub fn public_inputs(&self) -> noid_tx::PublicInputs {
        use noid_poseidon2b::primitives::TxBodyHash;

        // boundary_pins carries tx_body_hash as [Block128; 2]; the
        // combiner carries prev/new state roots likewise. Pack them
        // back into byte-digests for the PI wire format.
        let pack = |fields: [Block128; 2]| -> [u8; 32] {
            let mut out = [0u8; 32];
            out[..16].copy_from_slice(&fields[0].to_u128().to_le_bytes());
            out[16..].copy_from_slice(&fields[1].to_u128().to_le_bytes());
            out
        };

        // A1a — count live slots from the TxBody the trace was built
        // with. Matches the `is_live` logic used for T2a overrides and
        // the per-input/output valid-selector gates. `n_live_*` fits in
        // u8 because MAX_INPUTS / MAX_OUTPUTS are both < 256.
        let n_live_inputs = self.body.inputs.iter().filter(|inp| inp.valid).count() as u8;
        let n_live_outputs = self.body.outputs.iter().filter(|out| out.valid).count() as u8;

        // Stage E.6 — both combiner sides carry `log_slots` in their
        // preimages and the absorb-block AIR enforces that the declared
        // value matches the absorbed bytes. For a non-expansion block
        // the two sides agree by construction; the composite construction
        // path asserts it so the PublicInputs surface is unambiguous.
        let prev_log_slots = self.combiner.prev_preimage().log_slots;
        let new_log_slots = self.combiner.new_preimage().log_slots;
        assert_eq!(
            prev_log_slots, new_log_slots,
            "Stage E.6: prev/new combiner log_slots disagree \
             (expansion blocks are not yet supported in this composite)",
        );

        // Stage E.4 — activation / deactivation booleans. Mirror the
        // in-circuit `SKEL_IS_ACTIVATION_COL` / `SKEL_IS_DEACTIVATION_COL`
        // public-column programmes built by the leaf composite: an
        // input deactivates iff it is a live spend (`valid == true`);
        // an output activates iff it is a live mint (`valid == true`).
        // Dummy slots carry `false`. The in-circuit tie (to
        // `col_is_spend` / `col_is_mint` on opener rows) guarantees
        // the AIR rejects any prover who tries to flip a bit.
        let mut is_activation = [false; noid_tx::types::MAX_OUTPUTS];
        for (j, out) in self.body.outputs.iter().enumerate() {
            if j >= noid_tx::types::MAX_OUTPUTS {
                break;
            }
            is_activation[j] = out.valid;
        }
        let mut is_deactivation = [false; noid_tx::types::MAX_INPUTS];
        for (i, inp) in self.body.inputs.iter().enumerate() {
            if i >= noid_tx::types::MAX_INPUTS {
                break;
            }
            is_deactivation[i] = inp.valid;
        }

        noid_tx::PublicInputs {
            prev_state_root: pack(self.combiner.expected_prev_state_root_fields()),
            new_state_root: pack(self.combiner.expected_new_state_root_fields()),
            tx_body_hash: TxBodyHash(pack(self.boundary_pins.tx_body_hash)),
            fee: self.balance_fee as u128,
            n_live_inputs,
            n_live_outputs,
            // Stage E.5.f₄ — mirror of the f₄-pinned outer column. Zero
            // for regular txs (enforced by the `CreditZeroOnRegularGate`);
            // equal to `Σ outputs` on coinbase txs (enforced by the
            // `CreditEqualsB21SumGate`).
            coinbase_credit: self.coinbase_credit,
            // Stage E.6 — mirrored into the transcript so a prover
            // cannot silently resize the slot-space Merkle structure.
            log_slots: prev_log_slots,
            is_activation,
            is_deactivation,
        }
    }

    /// Stage 6 — assert that the caller-supplied `PublicInputs` is
    /// byte-identical to the pins already written into the sub-AIRs.
    /// Acceptance (c): every pin emitted exactly once, asserted at
    /// composite construction time.
    pub fn assert_public_inputs_consistent(&self, pi: &noid_tx::PublicInputs) {
        let derived = self.public_inputs();
        assert_eq!(
            derived.prev_state_root, pi.prev_state_root,
            "Stage 6: PublicInputs.prev_state_root disagrees with combiner pin",
        );
        assert_eq!(
            derived.new_state_root, pi.new_state_root,
            "Stage 6: PublicInputs.new_state_root disagrees with combiner pin",
        );
        assert_eq!(
            derived.tx_body_hash, pi.tx_body_hash,
            "Stage 6: PublicInputs.tx_body_hash disagrees with Merkle wrap-output pin",
        );
        assert_eq!(
            derived.fee, pi.fee,
            "Stage 6: PublicInputs.fee disagrees with balance-block pin",
        );
        assert_eq!(
            derived.coinbase_credit, pi.coinbase_credit,
            "Stage E.5.f₄: PublicInputs.coinbase_credit disagrees with credit-bit pin",
        );
        assert_eq!(
            derived.log_slots, pi.log_slots,
            "Stage E.6: PublicInputs.log_slots disagrees with combiner preimage",
        );
        assert_eq!(
            derived.is_activation, pi.is_activation,
            "Stage E.4: PublicInputs.is_activation disagrees with TxBody-derived live-mint vector",
        );
        assert_eq!(
            derived.is_deactivation, pi.is_deactivation,
            "Stage E.4: PublicInputs.is_deactivation disagrees with TxBody-derived live-spend vector",
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Honest fixture — exposed for the `noid_stark`
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
    use noid_poseidon2b::primitives::{
        derive_address, hash_auth_tag, hash_input_leaf as native_hash_input_leaf,
        hash_output_leaf as native_hash_output_leaf, hash_tx_body as native_hash_tx_body,
        SpendSecret, TxBodyHash as PrimTxBodyHash, TXBODY_INPUTS as P_TXBODY_INPUTS,
        TXBODY_OUTPUTS as P_TXBODY_OUTPUTS,
    };

    fn fields_to_bytes(fields: [Block128; 2]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&fields[0].to_u128().to_le_bytes());
        out[16..].copy_from_slice(&fields[1].to_u128().to_le_bytes());
        out
    }

    pub(super) fn native_address(secret: [Block128; 2]) -> [Block128; 2] {
        derive_address(&SpendSecret(fields_to_bytes(secret))).as_fields()
    }

    pub(super) fn native_auth_tag(
        secret: [Block128; 2],
        tx_body_hash: [Block128; 2],
    ) -> [Block128; 2] {
        hash_auth_tag(
            &SpendSecret(fields_to_bytes(secret)),
            &PrimTxBodyHash(fields_to_bytes(tx_body_hash)),
        )
        .as_fields()
    }

    fn owner_from_fields(hi: Block128, lo: Block128) -> noid_poseidon2b::primitives::Address {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&hi.to_u128().to_le_bytes());
        bytes[16..].copy_from_slice(&lo.to_u128().to_le_bytes());
        noid_poseidon2b::primitives::Address(bytes)
    }

    /// Native oracle for the tx-body wrap digest. Mirrors the GKR spine
    /// (which replaced the 59-perm AIR) by calling
    /// `noid_poseidon2b::primitives::hash_tx_body` on the absorb lanes
    /// carried in `pins`. `differential_vs_native` and
    /// `tx_body_hash_air_matches_native` keep this byte-for-byte locked
    /// with both the GKR reconstruction and the in-circuit wrap output.
    fn native_wrap_digest(pins: &TxBodyMerkleBoundaryPins) -> [Block128; 2] {
        let mut prev_state_root = [0u8; 32];
        prev_state_root[..16].copy_from_slice(&pins.prev_state_root[0].to_u128().to_le_bytes());
        prev_state_root[16..].copy_from_slice(&pins.prev_state_root[1].to_u128().to_le_bytes());

        let fee_u128 = pins.fee_leaf[0].to_u128();
        let is_coinbase = pins.is_coinbase_leaf[0].to_u128() != 0;

        let mut input_leaves = [[0u8; 32]; P_TXBODY_INPUTS];
        for i in 0..P_TXBODY_INPUTS {
            let [slot, value, owner_hi, owner_lo] = pins.input_leaf_absorb[i];
            let owner = owner_from_fields(owner_hi, owner_lo);
            input_leaves[i] =
                native_hash_input_leaf(slot.to_u128() as u32, value.to_u128() as u64, &owner);
        }
        let mut output_leaves = [[0u8; 32]; P_TXBODY_OUTPUTS];
        for j in 0..P_TXBODY_OUTPUTS {
            let [slot, value, owner_hi, owner_lo] = pins.output_leaf_absorb[j];
            let owner = owner_from_fields(owner_hi, owner_lo);
            output_leaves[j] =
                native_hash_output_leaf(slot.to_u128() as u32, value.to_u128() as u64, &owner);
        }

        let digest = native_hash_tx_body(
            &prev_state_root,
            fee_u128,
            &input_leaves,
            &output_leaves,
            is_coinbase,
        );
        let lo = u128::from_le_bytes(digest.0[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(digest.0[16..].try_into().unwrap());
        [Block128::from(lo), Block128::from(hi)]
    }

    pub fn empty_tx_body() -> TxBody {
        TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            is_coinbase: false,
        }
    }

    /// E.5.f₃ — coinbase counterpart of [`empty_tx_body`].
    pub fn empty_coinbase_tx_body() -> TxBody {
        TxBody {
            is_coinbase: true,
            ..empty_tx_body()
        }
    }

    /// E.5.f₃ — honest pins with `is_coinbase_leaf = [1, 0]`, for the
    /// coinbase test fixtures. Tx-body-hash is re-derived so the L14
    /// branch flips the wrap output correctly.
    pub fn honest_coinbase_pins_and_inputs() -> (
        TxBodyMerkleBoundaryPins,
        Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
    ) {
        let inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
            Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);
        let mut pins = TxBodyMerkleBoundaryPins {
            is_coinbase_leaf: [Block128::ONE, Block128::ZERO],
            ..TxBodyMerkleBoundaryPins::default()
        };
        pins.tx_body_hash = native_wrap_digest(&pins);
        (pins, inputs)
    }

    pub fn honest_pins_and_inputs() -> (
        TxBodyMerkleBoundaryPins,
        Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
    ) {
        let inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
            Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);
        let mut pins = TxBodyMerkleBoundaryPins::default();
        pins.tx_body_hash = native_wrap_digest(&pins);
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
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_secret(11), mk_secret(22), mk_secret(33), mk_secret(44)];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
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
        )
    }

    // D.1 — TxBody → boundary pins lowering.
    use noid_poseidon2b::primitives::{fee_leaf as native_fee_leaf, Address};
    use noid_tx::{TxInput, TxOutput, MAX_INPUTS as TX_MAX_INPUTS, MAX_OUTPUTS as TX_MAX_OUTPUTS};

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
        // E.5.f₂: L14 = [is_coinbase_as_u128, 0], matching
        // `noid_poseidon2b::primitives::is_coinbase_leaf`.
        pins.is_coinbase_leaf = [Block128::from(body.is_coinbase as u128), Block128::ZERO];
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
                Block128::from(out.slot_index as u128),
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
        let mut pins = TxBodyMerkleBoundaryPins::default();
        fill_absorb_pins_from_body(&mut pins, body);
        pins.tx_body_hash = native_wrap_digest(&pins);
        (pins, merkle_inputs)
    }

    pub fn address_from_fields(fields: [Block128; 2]) -> Address {
        Address(block128_pair_to_digest(fields))
    }

    /// Realistic non-empty TxBody honest composite.
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
        // Stage E.1: output slot_index is bound by the body hash and
        // lowered into `pins.output_leaf_absorb[j][0]`. Pick distinct
        // slots that don't collide with the live input slots.
        let out_slots: [u32; 4] = [1, 2, 4, 5];
        let outputs: Vec<TxOutput> = (0..8)
            .map(|j| {
                if j < 4 {
                    TxOutput {
                        slot_index: out_slots[j],
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
            is_coinbase: false,
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
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

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
        )
    }

    /// Max-capacity transaction: 4 live inputs, 8 live outputs.
    /// Inputs: slots 0,3,5,7 values 1000,500,250,125 (total 1875).
    /// Outputs: 8 recipients, values 400,300,200,150,100,75,50,25 (total 1300).
    /// Fee: 575. Balance: 1875 == 1300 + 575.
    pub fn build_honest_realistic_max() -> TxValidityCompositeWithSpine {
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

        let live_values: [u64; 4] = [1000, 500, 250, 125];
        let live_slots: [u32; 4] = [0, 3, 5, 7];
        let fee: u64 = 575;
        let out_values: [u64; 8] = [400, 300, 200, 150, 100, 75, 50, 25];

        let out_secrets: [[Block128; 2]; 8] = [
            mk_secret(0x10),
            mk_secret(0x20),
            mk_secret(0x30),
            mk_secret(0x40),
            mk_secret(0x50),
            mk_secret(0x60),
            mk_secret(0x70),
            mk_secret(0x80),
        ];
        let out_owners: [[Block128; 2]; 8] = [
            native_address(out_secrets[0]),
            native_address(out_secrets[1]),
            native_address(out_secrets[2]),
            native_address(out_secrets[3]),
            native_address(out_secrets[4]),
            native_address(out_secrets[5]),
            native_address(out_secrets[6]),
            native_address(out_secrets[7]),
        ];

        let inputs: Vec<TxInput> = (0..FRI_STATE_OPEN_N_INPUTS)
            .map(|i| TxInput {
                slot_index: live_slots[i],
                value: live_values[i],
                owner: address_from_fields(addrs[i]),
                spend_secret: SpendSecret(block128_pair_to_digest(secrets[i])),
                auth_tag: AuthTag([0u8; 32]),
                valid: true,
            })
            .collect();

        let out_slots: [u32; 8] = [1, 2, 4, 6, 8, 9, 10, 11];
        let outputs: Vec<TxOutput> = (0..8)
            .map(|j| TxOutput {
                slot_index: out_slots[j],
                value: out_values[j],
                owner: address_from_fields(out_owners[j]),
                valid: true,
            })
            .collect();

        let mut body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: fee as u128,
            inputs,
            outputs,
            is_coinbase: false,
        };

        let (pins, merkle_inputs) = lower_tx_body_to_pins(&body);
        let tx_body_hash = pins.tx_body_hash;

        let auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_auth_tag(secrets[0], tx_body_hash),
            native_auth_tag(secrets[1], tx_body_hash),
            native_auth_tag(secrets[2], tx_body_hash),
            native_auth_tag(secrets[3], tx_body_hash),
        ];
        for i in 0..4 {
            body.inputs[i].auth_tag = AuthTag(block128_pair_to_digest(auth_tags[i]));
        }

        let prev_preimage = mk_combiner_preimage(0xAB);
        let new_preimage = mk_combiner_preimage(0xBA);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            spend_with_owner(live_values[0] as u128, live_slots[0], addrs[0]),
            spend_with_owner(live_values[1] as u128, live_slots[1], addrs[1]),
            spend_with_owner(live_values[2] as u128, live_slots[2], addrs[2]),
            spend_with_owner(live_values[3] as u128, live_slots[3], addrs[3]),
        ];
        let base = FriStateOpenWitness::from_claims(claims)
            .with_eval_point(mk_eval_point())
            .with_gamma(mk_gamma());
        let prev_lane_openings = [
            Block128::from(0xAAAA_BBBB_CCCC_DDDD_u128),
            Block128::from(0x1111_2222_3333_4444_u128),
            Block128::from(0x5555_6666_7777_8888_u128),
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

        let balance_inputs: [u64; 4] = live_values;
        let balance_outputs: [u64; 8] = out_values;

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
        )
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::native_address;
    use super::fixture::{
        build_honest, build_honest_realistic, empty_coinbase_tx_body, empty_tx_body,
        honest_coinbase_pins_and_inputs, honest_pins_and_inputs, mk_combiner_preimage,
        mk_eval_point, mk_gamma, mk_secret, spend_with_owner,
    };
    use super::*;
    use crate::airs::fri_state_combiner::{
        build_combiner_side_trace, extract_combiner_digest_fields, COMBINER_PERM_LAYOUT,
    };
    use crate::airs::fri_state_open::FriStateOpenClaim;

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
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

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
        )
    }

    #[test]
    fn honest_trace_accepts_all_active_inputs() {
        let comp = build_honest_all_active();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    /// Realistic non-empty TxBody honest trace.
    #[test]
    fn honest_trace_accepts_realistic_tx_body() {
        let comp = build_honest_realistic();
        let trace = comp.build_trace();
        assert!(
            comp.air().check(&trace),
            "realistic non-empty TxBody honest trace must accept",
        );
    }

    #[test]
    fn layout_constants_agree() {
        assert_eq!(LEAF_BAND_RESERVED, TX_VALIDITY_LEAF_N_COLS);
        assert_eq!(SPINE_BLOCK_OUTER_BASE, LEAF_BAND_RESERVED);
        // E.5.f₄: one extra outer column for the coinbase-credit bit
        // programme, appended past the spine block.
        assert_eq!(
            tx_validity_with_spine_n_cols(),
            LEAF_BAND_RESERVED + spine_n_cols() + 1
        );
        assert_eq!(
            coinbase_credit_bit_col(),
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
        assert_eq!(layout.block_end(), coinbase_credit_bit_col());
        for input in 0..4 {
            let hi = layout.auth_tag_hi_outer_cell(input);
            let lo = layout.auth_tag_lo_outer_cell(input);
            assert!(hi.col >= layout.block_base() && hi.col < layout.block_end());
            assert!(lo.col >= layout.block_base() && lo.col < layout.block_end());
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
        trace.columns[wrap.col][wrap.row] = trace.columns[wrap.col][wrap.row] + Block128::ONE;
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

    /// Stage B.4 canonical regression: binding chain for output leaf payloads.
    ///
    /// `TxBodyMerkleAir` emits, for each lane ∈ {0,1}, a `PublicColumn` at
    /// `o1_base + TXBODY_MERKLE_O1_PROG_BASE_OFFSET + lane` whose programme
    /// row `output_leaf_perm_a_row(j)` carries `pins.output_leaf_absorb[j][lane]`.
    /// On that same row a `SelectorGate` (gated by `leaf_perm_a_row_0`)
    /// enforces `pre_s[lane] == o1_prog[lane]`. Together the programme-pin
    // `tamper_output_leaf_absorb_pin_rejects` was a regression for the
    // AIR-spine merkle-interior cells (O1 head-pin + pre_s[lane]).
    // Those cells no longer exist in the trace: GKR owns the
    // permutation soundness and the equivalent pin is `tx_body_hash`
    // at the wrap output. The cross-row leaf tamper coverage lives in
    // `noid_air/tests/output_binding_end_to_end.rs`.

    // -----------------------------------------------------------------
    // E.2.b.comp-4 exit tests — slot-index bridge.
    // -----------------------------------------------------------------
    //
    // Comp-3 threads live `TxOutput.slot_index/value/owner` into the
    // out-open block as mint claims; comp-4 pins each per-output
    // `col_idx_bit(k)` row directly to the declared slot-index bit.
    // Honest acceptance plus two tamper rejections close the audit
    // path: any deviation from the declared slot-index on the
    // out-open side is caught by the new `PublicColumn` programmes.

    /// E.2.b.comp-4 — honest realistic body-derived trace must accept.
    /// Redundant with `honest_trace_accepts_realistic_tx_body`, but
    /// named to document the comp-4 binding.
    #[test]
    fn comp4_honest_body_derived_trace_accepts() {
        let comp = build_honest_realistic();
        let trace = comp.build_trace();
        assert!(
            comp.air().check(&trace),
            "comp-4: honest body-derived trace must accept",
        );
    }

    /// E.2.b.comp-4 — flipping any out-open `col_idx_bit(k)` cell on
    /// an active output row must reject. Covers every (output, bit)
    /// pair to catch a silent no-op.
    #[test]
    fn comp4_out_open_slot_index_bit_tamper_rejects() {
        use crate::airs::fri_state_open::{FRI_STATE_OPEN_LOG_SLOTS, FRI_STATE_OPEN_OUTPUT_LAYOUT};
        use crate::composition::tx_validity_composite::SKEL_OUT_OPEN_COL_OFFSET;
        for output in 0..4 {
            for k in 0..FRI_STATE_OPEN_LOG_SLOTS {
                let comp = build_honest_realistic();
                let mut trace = comp.build_trace();
                let col = SKEL_OUT_OPEN_COL_OFFSET + FRI_STATE_OPEN_OUTPUT_LAYOUT.col_idx_bit(k);
                trace.columns[col][output] = trace.columns[col][output] + Block128::ONE;
                assert!(
                    !comp.air().check(&trace),
                    "comp-4: out-open idx_bit(k={k}) tamper at output {output} must REJECT",
                );
            }
        }
    }

    /// E.2.b.comp-4 — flipping the spine-side
    /// `TxValidityCol::SlotIndex[MAX_INPUTS + j]` cell must reject.
    /// The spine's `emit_txv_tx_body_public_columns` pins this cell to
    /// the declared `outputs[j].slot_index`; comp-4 pins the out-open
    /// `col_idx_bit` columns to the bits of the same declared value.
    /// Tampering either side breaks its own `PublicColumn` programme.
    #[test]
    fn comp4_spine_slot_index_tamper_rejects() {
        use crate::airs::tx_validity::TxValidityCol;
        use noid_tx::MAX_INPUTS;
        let comp = build_honest_realistic();
        let layout = comp.spine_layout();
        let txv_col_base = layout.txv_block_outer_offset();
        let slot_col = txv_col_base + TxValidityCol::SlotIndex.index();
        for j in 0..4 {
            let mut trace = comp.build_trace();
            let row = MAX_INPUTS + j;
            trace.columns[slot_col][row] = trace.columns[slot_col][row] + Block128::ONE;
            assert!(
                !comp.air().check(&trace),
                "comp-4: spine SlotIndex[MAX_INPUTS+{j}] tamper must REJECT",
            );
        }
    }

    // ---- E.5.d: coinbase WithSpine-level wiring ---------------------------

    /// Build a WithSpine composite with `is_coinbase = true`,
    /// `balance_fee = 0`, and every input slot empty — matches the
    /// canonical coinbase tx shape at the composite boundary.
    fn build_honest_coinbase() -> TxValidityCompositeWithSpine {
        use super::fixture::empty_with_owner;
        let (pins, merkle_inputs) = honest_coinbase_pins_and_inputs();

        let prev_preimage = mk_combiner_preimage(0x77);
        let new_preimage = mk_combiner_preimage(0x88);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_secret(11), mk_secret(22), mk_secret(33), mk_secret(44)];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];
        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            empty_with_owner(addrs[0]),
            empty_with_owner(addrs[1]),
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

        TxValidityCompositeWithSpine::new_with_options(
            pins,
            empty_coinbase_tx_body(),
            [0u64; 4],
            [0u64; 8],
            0,
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            WithSpineOptions {
                is_coinbase: true,
                coinbase_credit: 0,
            },
        )
    }

    #[test]
    fn e5d_honest_coinbase_accepts() {
        let comp = build_honest_coinbase();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
        // is_coinbase public column = ONE on every row.
        for row in 0..(1usize << TX_VALIDITY_WITH_SPINE_LOG_ROWS) {
            assert_eq!(trace.columns[SKEL_IS_COINBASE_COL][row], Block128::ONE);
        }
    }

    /// E.5.f₃ — tampering `pre_s[0]` at instance-42 row-0 (L14 seed)
    /// must reject on a coinbase trace.
    ///
    // `e5f3_coinbase_l14_pre_s_tamper_rejects` was a regression for
    // the AIR-spine O3.b pin on `pre_s[0..1]@instance-42`. GKR owns
    // the 59-perm permutation now — `is_coinbase_leaf` flows through
    // the spine into `tx_body_hash`, and the row-wide pin on
    // `TXBODY_MERKLE_LAYOUT.s` lanes catches any disagreement.

    /// E.5.f₃ — tampering the leaf-side `SKEL_IS_COINBASE_COL` scalar
    /// on any single row must reject on an honest coinbase trace.
    #[test]
    fn e5f3_skel_is_coinbase_col_tamper_rejects() {
        let comp = build_honest_coinbase();
        let trace = comp.build_trace();
        let mut cols = trace.columns.clone();
        // Flip the row that the bridge gate reads (instance-42 row-0 on
        // the Merkle side, but SKEL_IS_COINBASE_COL is row-constant so
        // flipping any row trips its own programme pin — which also
        // makes the bridge gate fire if we flip the same row).
        let layout_inst = crate::airs::tx_body_merkle::build_instance_layout();
        let row = layout_inst[42].slot_base_row;
        cols[SKEL_IS_COINBASE_COL][row] = cols[SKEL_IS_COINBASE_COL][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn e5d_non_coinbase_default_still_accepts() {
        // Regression: default-path `new()` keeps is_coinbase = false
        // and the fee-gate stays vacuous (fee bits · 0 == 0).
        let comp = build_honest();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
        for row in 0..(1usize << TX_VALIDITY_WITH_SPINE_LOG_ROWS) {
            assert_eq!(trace.columns[SKEL_IS_COINBASE_COL][row], Block128::ZERO);
        }
    }

    #[test]
    #[should_panic(expected = "is_coinbase = true requires balance_fee == 0")]
    fn e5d_coinbase_with_nonzero_fee_panics_at_construction() {
        // Data-safety sanity check: constructor rejects the wiring
        // mistake `is_coinbase = true` + `balance_fee != 0` before any
        // AIR is built.
        use super::fixture::empty_with_owner;
        let (pins, merkle_inputs) = honest_coinbase_pins_and_inputs();
        let prev_preimage = mk_combiner_preimage(0x01);
        let new_preimage = mk_combiner_preimage(0x02);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);
        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_secret(1), mk_secret(2), mk_secret(3), mk_secret(4)];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];
        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            empty_with_owner(addrs[0]),
            empty_with_owner(addrs[1]),
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
        let _ = TxValidityCompositeWithSpine::new_with_options(
            pins,
            empty_coinbase_tx_body(),
            [0u64; 4],
            [0u64; 8],
            7, // non-zero fee with is_coinbase=true → panic.
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            WithSpineOptions {
                is_coinbase: true,
                coinbase_credit: 0,
            },
        );
    }

    /// E.5.d.3 / E.5.f₄ — coinbase mint (inputs = 0, outputs > 0,
    /// fee = 0) must accept even though `Σ in ≠ Σ out`. Only the
    /// cross-chain A2↔B21 equality gates are silenced on coinbase; the
    /// rest of the balance circuit (per-block `bit_adder` internals,
    /// bridges, B-chain overflow guards) stays active. The fixture
    /// declares `coinbase_credit = 100` so the f₄
    /// `CreditEqualsB21SumGate` binds `B21.sum ≡ 100`.
    fn build_coinbase_mint() -> TxValidityCompositeWithSpine {
        use super::fixture::empty_with_owner;
        let (pins, merkle_inputs) = honest_coinbase_pins_and_inputs();
        let prev_preimage = mk_combiner_preimage(0x5D);
        let new_preimage = mk_combiner_preimage(0xD5);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);
        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_secret(1), mk_secret(2), mk_secret(3), mk_secret(4)];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];
        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            empty_with_owner(addrs[0]),
            empty_with_owner(addrs[1]),
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

        // Mint 100 — `Σ in = 0 ≠ 100 = Σ out`. Non-coinbase would reject.
        TxValidityCompositeWithSpine::new_with_options(
            pins,
            empty_coinbase_tx_body(),
            [0u64; 4],
            [100u64, 0, 0, 0, 0, 0, 0, 0],
            0,
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            WithSpineOptions {
                is_coinbase: true,
                coinbase_credit: 100,
            },
        )
    }

    #[test]
    fn e5d3_coinbase_mint_accepts_despite_unbalanced_ledger() {
        let comp = build_coinbase_mint();
        let trace = comp.build_trace();
        assert!(
            comp.air().check(&trace),
            "coinbase mint trace must accept even though Σin ≠ Σout (balance gates silenced)",
        );
    }

    /// E.5.d.3 — regression: non-coinbase with the same unbalanced
    /// shape must still reject. Confirms the negated-selector wrap
    /// only silences on `is_coinbase = 1`.
    #[test]
    fn e5d3_non_coinbase_mint_shape_rejects() {
        use super::fixture::empty_with_owner;
        let (pins, merkle_inputs) = honest_pins_and_inputs();
        let prev_preimage = mk_combiner_preimage(0x6E);
        let new_preimage = mk_combiner_preimage(0xE6);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);
        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_secret(10), mk_secret(20), mk_secret(30), mk_secret(40)];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];
        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            empty_with_owner(addrs[0]),
            empty_with_owner(addrs[1]),
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

        // Same mint shape but with is_coinbase = false: balance circuit
        // should reject Σin = 0 ≠ 100 = Σout.
        let comp = TxValidityCompositeWithSpine::new_with_options(
            pins,
            empty_tx_body(),
            [0u64; 4],
            [100u64, 0, 0, 0, 0, 0, 0, 0],
            0,
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            WithSpineOptions {
                is_coinbase: false,
                coinbase_credit: 0,
            },
        );
        let trace = comp.build_trace();
        assert!(
            !comp.air().check(&trace),
            "non-coinbase unbalanced trace must reject — negated selector must not leak",
        );
    }

    // -------- E.5.f₄ — coinbase-credit balance mux regressions --------

    /// (a) Honest coinbase with `Σ outputs == coinbase_credit` and
    /// `is_coinbase = 1` must accept. The `build_coinbase_mint` fixture
    /// declares `coinbase_credit = 100`, `outputs = [100, 0, ...]`.
    #[test]
    fn e5f4_honest_coinbase_with_credit_accepts() {
        let comp = build_coinbase_mint();
        let trace = comp.build_trace();
        assert!(
            comp.air().check(&trace),
            "E.5.f₄(a): honest coinbase with Σ outputs = coinbase_credit must accept",
        );
        // `PublicInputs.coinbase_credit` surfaces the declared value.
        assert_eq!(comp.public_inputs().coinbase_credit, 100);
    }

    /// (b) On a coinbase trace, tampering any bit of the pinned
    /// `coinbase_credit_bit_col` public programme must reject. The
    /// verifier-side `check_public_columns` rejects immediately; the
    /// native `check` does the equivalent via the `PublicColumn`
    /// programme equality.
    #[test]
    fn e5f4_coinbase_credit_bit_tamper_rejects() {
        let comp = build_coinbase_mint();
        let mut trace = comp.build_trace();
        let credit_col = coinbase_credit_bit_col();
        // 100 = 0b1100100 — bit 2 is ONE; flip it.
        trace.columns[credit_col][2] = trace.columns[credit_col][2] + Block128::ONE;
        assert!(!comp.air().check(&trace));
    }

    /// (c) Coinbase with `Σ outputs ≠ coinbase_credit` must reject —
    /// the construction-time assert catches the wiring mistake before
    /// any AIR is built. Constructing `coinbase_credit = 100` against
    /// `outputs = [99, 0, ...]` must panic.
    #[test]
    #[should_panic(expected = "Σ outputs must equal coinbase_credit")]
    fn e5f4_coinbase_sum_mismatch_panics_at_construction() {
        use super::fixture::empty_with_owner;
        let (pins, merkle_inputs) = honest_coinbase_pins_and_inputs();
        let prev_preimage = mk_combiner_preimage(0x31);
        let new_preimage = mk_combiner_preimage(0x32);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);
        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_secret(5), mk_secret(6), mk_secret(7), mk_secret(8)];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];
        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            empty_with_owner(addrs[0]),
            empty_with_owner(addrs[1]),
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
        let _ = TxValidityCompositeWithSpine::new_with_options(
            pins,
            empty_coinbase_tx_body(),
            [0u64; 4],
            [99u64, 0, 0, 0, 0, 0, 0, 0],
            0,
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            WithSpineOptions {
                is_coinbase: true,
                coinbase_credit: 100,
            },
        );
    }

    /// (c′) In-circuit: tampering `B21.sum` at an active row on an
    /// otherwise honest coinbase trace must reject. Catches the case
    /// where the prover honestly constructs the composite but then
    /// clobbers the sum cell to feign a different output total.
    #[test]
    fn e5f4_coinbase_b21_sum_tamper_rejects() {
        use crate::airs::balance_gate::BALANCE_BLK_B21;
        use crate::airs::bit_adder::{BIT_ADDER_COL_SUM, BIT_ADDER_N_COLS};
        use crate::airs::tx_body_spine::TXV_COL_OFFSET;
        use crate::airs::tx_validity::TX_VALIDITY_BALANCE_COL_OFFSET;

        let comp = build_coinbase_mint();
        let mut trace = comp.build_trace();
        let block_base = comp.spine_layout().block_base();
        let b21_sum_col = block_base
            + TXV_COL_OFFSET
            + TX_VALIDITY_BALANCE_COL_OFFSET
            + BALANCE_BLK_B21 * BIT_ADDER_N_COLS
            + BIT_ADDER_COL_SUM;
        trace.columns[b21_sum_col][1] = trace.columns[b21_sum_col][1] + Block128::ONE;
        assert!(!comp.air().check(&trace));
    }

    /// (d) Regression: a regular (non-coinbase) honest tx must still
    /// accept. Confirms the `CreditZeroOnRegularGate` holds when
    /// `coinbase_credit = 0` and the `CreditEqualsB21SumGate` is
    /// silenced by `is_coinbase = 0`.
    #[test]
    fn e5f4_regular_tx_still_accepts() {
        let comp = build_honest_realistic();
        let trace = comp.build_trace();
        assert!(
            comp.air().check(&trace),
            "E.5.f₄(d): regular tx regression — honest realistic trace must still accept",
        );
        assert_eq!(comp.public_inputs().coinbase_credit, 0);
    }

    /// Constructor data-safety: passing `coinbase_credit != 0` with
    /// `is_coinbase = false` must panic before any AIR is built.
    #[test]
    #[should_panic(expected = "coinbase_credit must be 0 when is_coinbase = false")]
    fn e5f4_regular_with_nonzero_credit_panics_at_construction() {
        use super::fixture::empty_with_owner;
        let (pins, merkle_inputs) = honest_pins_and_inputs();
        let prev_preimage = mk_combiner_preimage(0x11);
        let new_preimage = mk_combiner_preimage(0x22);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);
        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_secret(1), mk_secret(2), mk_secret(3), mk_secret(4)];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];
        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            empty_with_owner(addrs[0]),
            empty_with_owner(addrs[1]),
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
        let _ = TxValidityCompositeWithSpine::new_with_options(
            pins,
            empty_tx_body(),
            [0u64; 4],
            [0u64; 8],
            0,
            merkle_inputs,
            combiner,
            open_air,
            open_witness,
            WithSpineOptions {
                is_coinbase: false,
                coinbase_credit: 42,
            },
        );
    }

    #[test]
    fn e5d_coinbase_with_tampered_fee_bit_rejects() {
        // Honest coinbase trace carries `balance_fee = 0` — every bit
        // of the B21.b fee-column is zero. Flip one bit: the new
        // `CoinbaseNoFeeGate` sees `is_coinbase(=1) · fee_bit(=1) == 1`
        // → reject. Picks bit 0 on row 0 (instance 0, bit 0 of fee).
        use crate::airs::balance_gate::BALANCE_N_BLOCKS;
        use crate::airs::bit_adder::{BIT_ADDER_COL_B, BIT_ADDER_N_COLS};
        use crate::airs::tx_body_spine::TXV_COL_OFFSET;
        use crate::airs::tx_validity::TX_VALIDITY_BALANCE_COL_OFFSET;

        let comp = build_honest_coinbase();
        let mut trace = comp.build_trace();
        let block_base = comp.spine_layout().block_base();
        let blk_b21 = BALANCE_N_BLOCKS - 1;
        let fee_bit_col = block_base
            + TXV_COL_OFFSET
            + TX_VALIDITY_BALANCE_COL_OFFSET
            + blk_b21 * BIT_ADDER_N_COLS
            + BIT_ADDER_COL_B;
        trace.columns[fee_bit_col][0] = Block128::ONE;
        assert!(!comp.air().check(&trace));
    }
}
