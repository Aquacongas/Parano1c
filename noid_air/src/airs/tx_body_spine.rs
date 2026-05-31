//! `TxBodySpineComposite` — composite trace for wallet-side proving.
//!
//! Stitches the witness/balance block (width `TXV_BLOCK_N_COLS = 78`)
//! with `TxBodyMerkleAir::new_with_boundary_pins(pins)` into a single
//! AIR at `log_rows = 13`.
//!
//! # Column layout
//!
//! - `[0, TXV_BLOCK_N_COLS)` → witness + balance block (width 78).
//! - `[TX_BODY_MERKLE_COL_OFFSET, TX_BODY_MERKLE_COL_OFFSET + MERKLE_BAND_WIDTH)`
//!   → TxBodyMerkle band (two `tx_body_hash` lanes; GKR owns the
//!   59-perm soundness).
//! - tail column → `TxvLiveMask` `PublicColumn`.

use crate::airs::tx_body_merkle::{
    TxBodyMerkleBoundaryPins, TXBODY_MERKLE_LAYOUT, TXBODY_MERKLE_LOG_ROWS, TXBODY_MERKLE_N_PERMS,
};
use crate::gates::PublicColumn;
use crate::{Air, ColumnDomain, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::{Block128, TowerField};
use noid_tx::types::TxBody;
use noid_tx::{MAX_INPUTS, MAX_OUTPUTS};

/// Column offset of the witness/balance block. Zero by convention.
pub const TXV_COL_OFFSET: usize = 0;

/// Width of the witness + balance block inside the composite.
/// = TX_VALIDITY_N_COLS(10) + BALANCE_N_COLS(66) + 2 mask cols = 78.
/// Previously `TXV_BLOCK_N_COLS` from the legacy AIR.
pub const TXV_BLOCK_N_COLS: usize = 78;

/// Column offset of the TxBodyMerkle block inside the composite.
pub const TX_BODY_MERKLE_COL_OFFSET: usize = TXV_BLOCK_N_COLS;

/// Witness region row count at the floor log_rows = 8: rows
/// `[0, TXV_LIVE_ROWS)` carry live witness; rows `[TXV_LIVE_ROWS, 2^13)`
/// are the dead tail.
pub const TXV_LIVE_ROWS: usize = 1 << 8;

/// Composite `log_rows`, fixed to the TxBodyMerkle native value.
pub const SPINE_LOG_ROWS: usize = TXBODY_MERKLE_LOG_ROWS;

// ---------------------------------------------------------------------------
// Column indices for witness fields inside the composite trace.
// These match the original TxValidityCol enum values.
// ---------------------------------------------------------------------------

const COL_SLOT_INDEX: usize = TXV_COL_OFFSET + 2;
const COL_VALUE: usize = TXV_COL_OFFSET + 3;
const COL_OWNER_HI: usize = TXV_COL_OFFSET + 4;
const COL_OWNER_LO: usize = TXV_COL_OFFSET + 5;
const COL_AUTH_TAG_HI: usize = TXV_COL_OFFSET + 8;
const COL_AUTH_TAG_LO: usize = TXV_COL_OFFSET + 9;

// Column indices for the two row-domain mask columns
// (the "+2" in TXV_BLOCK_N_COLS = 10 + 66 + 2).
const COL_INPUT_VALID: usize = TXV_COL_OFFSET + 0;
const COL_OUTPUT_VALID: usize = TXV_COL_OFFSET + 1;
const COL_INPUT_VALID_MASK: usize = TXV_COL_OFFSET + 76; // TX_VALIDITY_3B4_N_COLS = 76
const COL_OUTPUT_VALID_MASK: usize = TXV_COL_OFFSET + 77;
const TX_VALIDITY_N_COLS: usize = 10;
const BALANCE_COL_OFFSET: usize = TX_VALIDITY_N_COLS; // = 10

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

/// Stage 2(b) — programme for one of the four tx-body witness columns
/// (slot_index=2, value=3, owner_hi=4, owner_lo=3), derived from
/// `TxBodyMerkleBoundaryPins.{input,output}_leaf_absorb`.
///
/// `lane` is the index into each leaf_absorb tuple: 0=slot_index,
/// 1=value, 2=owner_hi, 3=owner_lo.
fn txv_tx_body_col_programme(lane: usize, pins: &TxBodyMerkleBoundaryPins) -> Vec<Block128> {
    let total = 1usize << SPINE_LOG_ROWS;
    let mut out = vec![Block128::ZERO; total];
    for i in 0..MAX_INPUTS {
        out[i] = pins.input_leaf_absorb[i][lane];
    }
    for j in 0..MAX_OUTPUTS {
        out[MAX_INPUTS + j] = pins.output_leaf_absorb[j][lane];
    }
    out
}

/// Stage 2(b) — emit the four `PublicColumn`s that pin tx-body
/// witness columns to the Stage-1b leaf-absorb pins.
pub fn emit_txv_tx_body_public_columns(pins: &TxBodyMerkleBoundaryPins) -> Vec<PublicColumn> {
    // col indices: slot_index=COL_SLOT_INDEX(2), value=COL_VALUE(3),
    //              owner_hi=COL_OWNER_HI(4), owner_lo=COL_OWNER_LO(5).
    [COL_SLOT_INDEX, COL_VALUE, COL_OWNER_HI, COL_OWNER_LO]
        .into_iter()
        .enumerate()
        .map(|(lane, col)| PublicColumn::new(col, txv_tx_body_col_programme(lane, pins)))
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

/// Width of the merkle sub-AIR band inside the spine composite:
/// exactly the two `tx_body_hash` lanes on `TXBODY_MERKLE_LAYOUT.s` /
/// `.s + 1`. The 59-perm trace is retired — GKR owns the permutation
/// soundness and produces `tx_body_hash` as its wrap output. The STARK
/// retains only the two PC lanes, which by construction resolve
/// bit-for-bit to the same `(merkle_offset + lane, row)` cells that
/// `wrap_output_outer_cell` expects.
pub fn merkle_band_width() -> usize {
    MERKLE_BAND_WIDTH
}

/// Retained merkle-band lane count. Exactly the two `tx_body_hash`
/// lanes on `TXBODY_MERKLE_LAYOUT.s` / `.s + 1`; every other
/// merkle-interior cell is physically removed from the trace.
pub const MERKLE_BAND_WIDTH: usize = 2;

/// Column index of `TxvLiveMask` inside the composite trace.
pub fn txv_live_mask_col() -> usize {
    TX_BODY_MERKLE_COL_OFFSET + merkle_band_width()
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
    pub fn new(pins: TxBodyMerkleBoundaryPins) -> Self {
        use crate::airs::balance_gate::{
            emit_balance_constraints, emit_balance_selector_public_columns,
        };
        use crate::gates::{emit_rows_must_be_zero, BoolGate};

        let log_rows = SPINE_LOG_ROWS;
        let n_rows = 1usize << log_rows;

        // --- Witness + balance constraints (replaces TxValidityAir) ---
        let mut txv_constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(COL_INPUT_VALID)),
            Box::new(BoolGate::new(COL_OUTPUT_VALID)),
        ];
        txv_constraints.extend(emit_balance_constraints(BALANCE_COL_OFFSET));

        let mut txv_publics: Vec<PublicColumn> =
            emit_balance_selector_public_columns(BALANCE_COL_OFFSET, log_rows);

        // Row-domain mask for InputValid: forbidden rows MAX_INPUTS..n_rows
        let input_forbidden: Vec<usize> = (MAX_INPUTS..n_rows).collect();
        let (pc_in, g_in) = emit_rows_must_be_zero(
            COL_INPUT_VALID_MASK,
            &input_forbidden,
            n_rows,
            COL_INPUT_VALID,
        );
        txv_publics.push(pc_in);
        txv_constraints.push(g_in);

        // Row-domain mask for OutputValid: forbidden rows 0..MAX_INPUTS ∪ MAX_INPUTS+MAX_OUTPUTS..n_rows
        let mut output_forbidden: Vec<usize> = (0..MAX_INPUTS).collect();
        output_forbidden.extend((MAX_INPUTS + MAX_OUTPUTS)..n_rows);
        let (pc_out, g_out) = emit_rows_must_be_zero(
            COL_OUTPUT_VALID_MASK,
            &output_forbidden,
            n_rows,
            COL_OUTPUT_VALID,
        );
        txv_publics.push(pc_out);
        txv_constraints.push(g_out);

        let merkle_n_cols = merkle_band_width();

        assert_eq!(TXV_COL_OFFSET, 0);
        assert_eq!(TX_BODY_MERKLE_COL_OFFSET, TXV_BLOCK_N_COLS);
        let mask_col = txv_live_mask_col();
        assert_eq!(mask_col, TX_BODY_MERKLE_COL_OFFSET + merkle_n_cols);

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // TXV block at offset 0 — ShiftedColumnsConstraint is identity at offset 0.
        for c in txv_constraints {
            constraints.push(Box::new(ShiftedColumnsConstraint::new(
                c,
                TXV_COL_OFFSET,
                TXV_BLOCK_N_COLS,
            )));
        }
        for pc in txv_publics {
            assert!(pc.col < TXV_BLOCK_N_COLS);
            public_columns.push(PublicColumn::new(pc.col + TXV_COL_OFFSET, pc.values));
        }

        // TxBodyMerkle band — the 59-perm trace is retired. GKR owns
        // the full 59-perm soundness and produces `tx_body_hash` as its
        // wrap output. The STARK keeps the binding as two row-wide
        // `PublicColumn`s at `TXBODY_MERKLE_LAYOUT.s` / `.s + 1` so
        // every consumer that reads `wrap_output_outer_cell(lane)` sees
        // the verifier-known scalar on every row.
        {
            let _ = merkle_n_cols;
            let total_rows = 1usize << SPINE_LOG_ROWS;
            for lane in 0..2usize {
                let col = TX_BODY_MERKLE_COL_OFFSET + TXBODY_MERKLE_LAYOUT.s + lane;
                public_columns.push(PublicColumn::new(
                    col,
                    vec![pins.tx_body_hash[lane]; total_rows],
                ));
            }
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

    /// Consume the composite and surrender its constraints, public
    /// columns, total column count, and boundary pins. Used by the
    /// Stage 5.7 `TxValidityCompositeWithSpine` to embed the spine as
    /// a column-block inside a wider outer composite — the outer
    /// shifts each constraint and public column by the spine block's
    /// outer offset and rebuilds its own [`crate::CompositeAir`].
    /// `boundary_pins` are returned so the embedder can rebuild the
    /// trace via [`Self::build_trace`] without having to keep the
    /// composite alive.
    pub fn into_parts(
        self,
    ) -> (
        usize,
        Vec<Box<dyn Constraint>>,
        Vec<PublicColumn>,
        TxBodyMerkleBoundaryPins,
    ) {
        (
            self.n_cols,
            self.constraints,
            self.public_columns,
            self.boundary_pins,
        )
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
        use crate::airs::balance_gate::build_balance_columns;
        use crate::gates::multi_row_indicator_programme;

        // --- Build witness + balance + mask trace (replaces TxValidityAir::build_trace_3b4_with_skeleton_pins) ---
        let log_rows = SPINE_LOG_ROWS;
        let n_rows = 1usize << log_rows;

        // Witness columns [0, TX_VALIDITY_N_COLS)
        let mut cols: Vec<Vec<Block128>> = (0..TX_VALIDITY_N_COLS)
            .map(|_| vec![Block128::ZERO; n_rows])
            .collect();
        let mut domains = vec![ColumnDomain::Block128; TX_VALIDITY_N_COLS];
        domains[COL_INPUT_VALID] = ColumnDomain::Bit;
        domains[COL_OUTPUT_VALID] = ColumnDomain::Bit;

        for (i, input) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
            if !input.valid {
                continue;
            }
            cols[COL_INPUT_VALID][i] = Block128::ONE;
            cols[COL_SLOT_INDEX - TXV_COL_OFFSET][i] = Block128::from(input.slot_index as u128);
            cols[COL_VALUE - TXV_COL_OFFSET][i] = Block128::from(input.value as u128);
            let [oh, ol] = input.owner.as_fields();
            cols[COL_OWNER_HI - TXV_COL_OFFSET][i] = oh;
            cols[COL_OWNER_LO - TXV_COL_OFFSET][i] = ol;
            let [sh, sl] = input.spend_secret.as_fields();
            cols[6][i] = sh; // SpendSecretHi
            cols[7][i] = sl; // SpendSecretLo
            let [th, tl] = input.auth_tag.as_fields();
            cols[COL_AUTH_TAG_HI - TXV_COL_OFFSET][i] = th;
            cols[COL_AUTH_TAG_LO - TXV_COL_OFFSET][i] = tl;
        }
        for (j, output) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
            if !output.valid {
                continue;
            }
            let row = MAX_INPUTS + j;
            cols[COL_OUTPUT_VALID][row] = Block128::ONE;
            cols[COL_SLOT_INDEX - TXV_COL_OFFSET][row] = Block128::from(output.slot_index as u128);
            cols[COL_VALUE - TXV_COL_OFFSET][row] = Block128::from(output.value as u128);
            let [oh, ol] = output.owner.as_fields();
            cols[COL_OWNER_HI - TXV_COL_OFFSET][row] = oh;
            cols[COL_OWNER_LO - TXV_COL_OFFSET][row] = ol;
        }

        // Balance columns [TX_VALIDITY_N_COLS, TX_VALIDITY_N_COLS + BALANCE_N_COLS)
        let (balance_cols, balance_domains) =
            build_balance_columns(balance_inputs, balance_outputs, balance_fee, log_rows);
        cols.extend(balance_cols);
        domains.extend(balance_domains);

        // Row-domain mask indicator columns (2 extra)
        let input_forbidden: Vec<usize> = (MAX_INPUTS..n_rows).collect();
        let mut output_forbidden: Vec<usize> = (0..MAX_INPUTS).collect();
        output_forbidden.extend((MAX_INPUTS + MAX_OUTPUTS)..n_rows);
        cols.push(multi_row_indicator_programme(&input_forbidden, n_rows));
        cols.push(multi_row_indicator_programme(&output_forbidden, n_rows));
        domains.push(ColumnDomain::Bit);
        domains.push(ColumnDomain::Bit);

        assert_eq!(cols.len(), TXV_BLOCK_N_COLS);

        // G4: GKR owns the 59-perm soundness. STARK keeps only the two
        // tx_body_hash lanes as row-wide PublicColumns.
        let _ = merkle_inputs;
        let total_rows = 1usize << SPINE_LOG_ROWS;
        let mut merkle_cols: Vec<Vec<Block128>> = (0..merkle_band_width())
            .map(|_| vec![Block128::ZERO; total_rows])
            .collect();
        for lane in 0..2usize {
            merkle_cols[TXBODY_MERKLE_LAYOUT.s + lane] =
                vec![self.boundary_pins.tx_body_hash[lane]; total_rows];
        }
        let merkle_domains = vec![ColumnDomain::Block128; merkle_band_width()];

        cols.extend(merkle_cols);
        domains.extend(merkle_domains);
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
    fn column_domains(&self) -> Vec<ColumnDomain> {
        use crate::airs::balance_gate::BALANCE_N_COLS;
        let mut domains = vec![ColumnDomain::Block128; TX_VALIDITY_N_COLS];
        domains[COL_INPUT_VALID] = ColumnDomain::Bit;
        domains[COL_OUTPUT_VALID] = ColumnDomain::Bit;
        // Balance block: all BitAdder → all Bit
        domains.extend(vec![ColumnDomain::Bit; BALANCE_N_COLS]);
        // Two row-domain mask columns
        domains.push(ColumnDomain::Bit);
        domains.push(ColumnDomain::Bit);
        // Merkle band (tx_body_hash lanes)
        domains.extend(vec![ColumnDomain::Block128; MERKLE_BAND_WIDTH]);
        // TxvLiveMask
        domains.push(ColumnDomain::Bit);
        debug_assert_eq!(domains.len(), self.n_cols);
        domains
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{
        hash_input_leaf as native_hash_input_leaf, hash_output_leaf as native_hash_output_leaf,
        hash_tx_body as native_hash_tx_body, TXBODY_INPUTS as P_TXBODY_INPUTS,
        TXBODY_OUTPUTS as P_TXBODY_OUTPUTS,
    };

    fn empty_tx_body() -> TxBody {
        TxBody {
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            is_coinbase: false,
        }
    }

    fn owner_from_fields(hi: Block128, lo: Block128) -> noid_poseidon2b::primitives::Address {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&hi.to_u128().to_le_bytes());
        bytes[16..].copy_from_slice(&lo.to_u128().to_le_bytes());
        noid_poseidon2b::primitives::Address(bytes)
    }

    /// Native oracle for the tx-body wrap digest. Mirrors the GKR spine
    /// (production path) by calling
    /// `noid_poseidon2b::primitives::hash_tx_body` on the absorb lanes
    /// carried in `pins`. Byte-identical with the GKR reconstruction.
    fn native_wrap_digest(pins: &TxBodyMerkleBoundaryPins) -> [Block128; 2] {
        let mut epoch_anchor = [0u8; 32];
        epoch_anchor[..16].copy_from_slice(&pins.epoch_anchor[0].to_u128().to_le_bytes());
        epoch_anchor[16..].copy_from_slice(&pins.epoch_anchor[1].to_u128().to_le_bytes());

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
            &epoch_anchor,
            fee_u128,
            &input_leaves,
            &output_leaves,
            is_coinbase,
        );
        let lo = u128::from_le_bytes(digest.0[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(digest.0[16..].try_into().unwrap());
        [Block128::from(lo), Block128::from(hi)]
    }

    /// Derive an internally-consistent `(pins, merkle_inputs)` pair by
    /// asking the native Poseidon2b oracle for the wrap digest. The
    /// `merkle_inputs` array is legacy residue left for callers that
    /// still thread it into `build_trace`; it is no longer consumed on
    /// the AIR side once the 59-perm chain was handed to GKR.
    fn build_honest_pins_and_inputs() -> (
        TxBodyMerkleBoundaryPins,
        Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]>,
    ) {
        let inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
            Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);
        let mut pins = TxBodyMerkleBoundaryPins::default();
        pins.tx_body_hash = native_wrap_digest(&pins);
        (pins, inputs)
    }

    #[test]
    fn composite_layout_constants() {
        assert_eq!(TXV_COL_OFFSET, 0);
        assert_eq!(TX_BODY_MERKLE_COL_OFFSET, TXV_BLOCK_N_COLS);
        assert_eq!(TX_BODY_MERKLE_COL_OFFSET, 78);
        assert_eq!(SPINE_LOG_ROWS, 13);
        assert_eq!(TXV_LIVE_ROWS, 256);
        let n = spine_n_cols();
        assert_eq!(n, TXV_BLOCK_N_COLS + merkle_band_width() + 1);
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

        // Every row of the retained wrap-output lane is pinned to
        // `pins.tx_body_hash[0]` by a PublicColumn, so any row-level
        // tamper in that column must reject.
        let col = TX_BODY_MERKLE_COL_OFFSET + TXBODY_MERKLE_LAYOUT.s;
        trace.columns[col][0] += Block128::ONE;
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

        // Stage E.1: output leaf absorbs 4 fields symmetric with input.
        let out_slot: u32 = 1;
        let mut output_leaf_absorb = [[Block128::ZERO; 4]; 8];
        output_leaf_absorb[0] = [
            Block128::from(out_slot as u128),
            Block128::from(value as u128),
            out_owner_hi,
            out_owner_lo,
        ];

        // Derive the wrap digest via the native Poseidon2b oracle — the
        // same kernel the GKR spine evaluates in circuit.
        let merkle_inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
            Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);
        let mut pins = TxBodyMerkleBoundaryPins {
            tx_body_hash: [Block128::ZERO; 2],
            input_leaf_absorb,
            output_leaf_absorb,
            ..TxBodyMerkleBoundaryPins::default()
        };
        pins.tx_body_hash = native_wrap_digest(&pins);

        let body = TxBody {
            epoch_anchor: [0u8; 32],
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
                    slot_index: 1,
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
            is_coinbase: false,
        };

        (body, pins, merkle_inputs)
    }

    /// Stage 5.7 invariant guard: `AuthTagHi` / `AuthTagLo` (composite
    /// cols 8 / 9) must remain witness-only on the spine side. They
    /// are pinned through the external `AuthGKR` boundary and must
    /// never be declared as a `PublicColumn` — doing so would
    /// re-introduce the "third source of truth" the audit § 1 warns
    /// about (PI vs Merkle vs GKR pin).
    #[test]
    fn stage_5_7_invariant_auth_tag_columns_are_not_pi_pinned() {
        let (pins, _inputs) = build_honest_pins_and_inputs();
        let spine = TxBodySpineComposite::new(pins);

        let auth_hi = COL_AUTH_TAG_HI;
        let auth_lo = COL_AUTH_TAG_LO;
        assert_eq!(auth_hi, 8, "AuthTagHi composite col drifted from 8");
        assert_eq!(auth_lo, 9, "AuthTagLo composite col drifted from 9");

        for pc in spine.public_columns() {
            assert_ne!(
                pc.col, auth_hi,
                "AuthTagHi (col 8) is PI-pinned — Stage 5.7 invariant broken"
            );
            assert_ne!(
                pc.col, auth_lo,
                "AuthTagLo (col 9) is PI-pinned — Stage 5.7 invariant broken"
            );
        }
    }

    /// Stage 5.7 invariant guard: `tx_body_hash` must remain
    /// single-origin on the Merkle side (wrap-perm output) inside the
    /// spine. The TxValidity block must not redundantly pin
    /// `tx_body_hash` to any of its witness columns — the hash is
    /// consumed downstream only through the external `AuthGKR`
    /// boundary, never through a parallel PublicColumn.
    #[test]
    fn stage_5_7_invariant_tx_body_hash_single_origin() {
        let (pins, _inputs) = build_honest_pins_and_inputs();
        let spine = TxBodySpineComposite::new(pins);
        let merkle_n_cols = merkle_band_width();
        let merkle_lo = TX_BODY_MERKLE_COL_OFFSET;
        let merkle_hi = TX_BODY_MERKLE_COL_OFFSET + merkle_n_cols;

        let canonical_hi = pins.tx_body_hash[0];
        let canonical_lo = pins.tx_body_hash[1];
        for pc in spine.public_columns() {
            if pc.col >= merkle_lo && pc.col < merkle_hi {
                continue; // Merkle block — canonical origin
            }
            for v in &pc.values {
                if *v == Block128::ZERO {
                    continue; // ZERO collisions allowed on all-zero fixtures
                }
                assert_ne!(
                    *v, canonical_hi,
                    "tx_body_hash[0] leaked into non-Merkle PublicColumn at col {}",
                    pc.col
                );
                assert_ne!(
                    *v, canonical_lo,
                    "tx_body_hash[1] leaked into non-Merkle PublicColumn at col {}",
                    pc.col
                );
            }
        }
    }

    #[test]
    fn stage_2b_declares_four_txv_tx_body_public_columns() {
        let (_body, pins, _inputs) = honest_stage2b_fixture();
        let spine = TxBodySpineComposite::new(pins);

        // Every TxValidity tx-body column must be among the composite
        // public columns at the TxValidity offset.
        let expected_cols = [COL_SLOT_INDEX, COL_VALUE, COL_OWNER_HI, COL_OWNER_LO];
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
        let col = COL_SLOT_INDEX;
        trace.columns[col][0] += Block128::ONE;
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
        // Flip Value on output row 0 — pinned to output_leaf_absorb[0][1].
        let col = COL_VALUE;
        let row = MAX_INPUTS;
        trace.columns[col][row] += Block128::ONE;
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
        let col = COL_OWNER_HI;
        trace.columns[col][0] += Block128::ONE;
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
        let col = COL_OWNER_LO;
        let row = MAX_INPUTS;
        trace.columns[col][row] += Block128::ONE;
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
        let col = COL_VALUE;
        let row = TXV_LIVE_ROWS + 42; // deep in the dead tail
        trace.columns[col][row] = Block128::from(0xBADu128);
        assert!(
            !spine.check(&trace),
            "Stage 2(b) pins must force dead-tail Value cells to ZERO"
        );
    }
}
