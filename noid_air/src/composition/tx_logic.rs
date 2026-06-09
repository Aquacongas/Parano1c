// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `TxLogicAir` — stateless per-transaction logic AIR for wallet-side proofs.
//!
//! This is the AIR the wallet proves against in the two-layer architecture.
//! It enforces UTXO conservation (balance), value range bounds, selector
//! domain constraints, and the body-hash pin — but contains NO state columns.
//! FriStateCombiner, FriStateOpen, and all state-opening machinery live
//! exclusively in the miner-side `BlockStateBindingAir`.
//!
//! Structurally, `TxLogicAir` is the existing `TxBodySpineComposite`: it
//! stitches `TxValidityAir` (balance + selectors) with the retained
//! body-hash `PublicColumn` lanes and the `TxvLiveMask` column at
//! `log_rows = 11`. GKR owns the 59-perm Poseidon2b Merkle spine; the
//! STARK proves the balance/validity constraints and pins the body-hash
//! output via public columns.
//!
//! # Column layout
//!
//! Identical to `TxBodySpineComposite`:
//! - `[0, TX_VALIDITY_3B4_PINNED_N_COLS)` → TxValidity block (balance + selectors)
//! - `[TX_BODY_MERKLE_COL_OFFSET, +2)` → retained body-hash lanes (PublicColumn)
//! - tail column → `TxvLiveMask` PublicColumn
//!
//! # Why log_rows is 11 (not 13)
//!
//! The 59-perm Merkle trace was retired from the STARK (GKR owns it).
//! `TxBodyMerkleBoundaryPins` fields are fixed-size arrays, not scaled
//! by `log_rows`. The balance gate requires `log_rows ≥ 8`; setting
//! `SPINE_LOG_ROWS = 11` (2048 rows) fits the entire composite working
//! set in L3 cache and reduces FRI rounds from 5 → 3.

use crate::airs::tx_body_merkle::TxBodyMerkleBoundaryPins;
use crate::airs::tx_body_spine::{
    TxBodySpineComposite, MERKLE_BAND_WIDTH, SPINE_LOG_ROWS, TX_BODY_MERKLE_COL_OFFSET,
};
use crate::{Air, Trace};
use noid_core::{Block128, TowerField};
use noid_tx::TxBody;

/// Log-rows of the TxLogicAir trace. Matches `SPINE_LOG_ROWS = 11`.
pub const TX_LOGIC_LOG_ROWS: usize = SPINE_LOG_ROWS;

/// Total column count of the TxLogicAir trace.
/// = TX_BODY_MERKLE_COL_OFFSET + MERKLE_BAND_WIDTH + 1 (TxvLiveMask)
pub const TX_LOGIC_N_COLS: usize = TX_BODY_MERKLE_COL_OFFSET + MERKLE_BAND_WIDTH + 1;

/// Stateless logic AIR for wallet-side proofs. Wraps `TxBodySpineComposite`
/// with a focused construction API that takes `TxBody` + balance operands
/// directly.
pub struct TxLogicAir {
    inner: TxBodySpineComposite,
}

/// Witness bundle for constructing a `TxLogicAir` and its honest trace.
#[derive(Clone)]
pub struct TxLogicWitness {
    pub body: TxBody,
    pub boundary_pins: TxBodyMerkleBoundaryPins,
    pub balance_inputs: [u64; 4],
    pub balance_outputs: [u64; 8],
    pub balance_fee: u64,
}

impl TxLogicAir {
    /// Construct the logic AIR from boundary pins. The pins carry all
    /// verifier-known scalars (body-hash, leaf absorbs, epoch_anchor fields)
    /// that the spine composite needs to declare its public columns.
    pub fn new(pins: TxBodyMerkleBoundaryPins) -> Self {
        Self {
            inner: TxBodySpineComposite::new(pins),
        }
    }

    /// Build the honest trace from a `TxLogicWitness`.
    pub fn build_trace(&self, witness: &TxLogicWitness) -> Trace {
        self.inner.build_trace(
            &witness.body,
            witness.balance_inputs,
            witness.balance_outputs,
            witness.balance_fee,
        )
    }

    /// Access the inner composite's boundary pins.
    pub fn boundary_pins(&self) -> &TxBodyMerkleBoundaryPins {
        self.inner.boundary_pins()
    }

    /// Consume into the inner `TxBodySpineComposite` for downstream use.
    pub fn into_inner(self) -> TxBodySpineComposite {
        self.inner
    }
}

impl Air for TxLogicAir {
    fn n_columns(&self) -> usize {
        self.inner.n_columns()
    }

    fn log_rows(&self) -> usize {
        self.inner.log_rows()
    }

    fn constraints(&self) -> &[Box<dyn crate::Constraint>] {
        self.inner.constraints()
    }

    fn public_columns(&self) -> &[crate::gates::const_column::PublicColumn] {
        self.inner.public_columns()
    }

    fn fixed_columns(&self) -> Vec<usize> {
        // Fixed columns are identical across all transactions:
        // - Column 0: COL_INPUT_VALID (selector for inputs)
        // - Column 1: COL_OUTPUT_VALID (selector for outputs)
        // - Column 76: COL_INPUT_VALID_MASK (mask for inputs)
        // - Column 77: COL_OUTPUT_VALID_MASK (mask for outputs)
        // - Column 80: TxvLiveMask (mask for live rows)
        //
        // Per-tx public columns (depend on tx_body_hash):
        // - Columns 78-79: tx_body_hash lanes
        //
        // Witness columns (per-tx, mutable):
        // - Columns 2-75: balance, range, carry chains, bit adders
        vec![0, 1, 76, 77, 80]
    }
}

// ---------------------------------------------------------------------------
// Construction helpers
// ---------------------------------------------------------------------------

/// Build `TxBodyMerkleBoundaryPins` from a `TxBody` using the native
/// Poseidon2b oracle. This is the wallet-side construction path: derive
/// the boundary pins from the transaction body so the AIR and GKR spine
/// are instantiated against the same scalars.
pub fn boundary_pins_from_body(body: &TxBody) -> TxBodyMerkleBoundaryPins {
    use noid_poseidon2b::primitives::{
        hash_input_leaf, hash_output_leaf, hash_tx_body, TXBODY_INPUTS, TXBODY_OUTPUTS,
    };
    use noid_tx::{MAX_INPUTS, MAX_OUTPUTS};

    let mut pins = TxBodyMerkleBoundaryPins::default();

    // Epoch anchor fields
    let ea_hi = u128::from_le_bytes(body.epoch_anchor[..16].try_into().unwrap());
    let ea_lo = u128::from_le_bytes(body.epoch_anchor[16..].try_into().unwrap());
    pins.epoch_anchor = [Block128::from(ea_hi), Block128::from(ea_lo)];

    // Fee leaf
    pins.fee_leaf = [Block128::from(body.fee), Block128::ZERO];

    // Is-coinbase leaf
    pins.is_coinbase_leaf = [Block128::from(body.is_coinbase as u128), Block128::ZERO];

    // Input leaf absorbs
    for i in 0..MAX_INPUTS.min(TXBODY_INPUTS) {
        let inp = body
            .inputs
            .get(i)
            .cloned()
            .unwrap_or_else(noid_tx::TxInput::dummy);
        let [owner_hi, owner_lo] = inp.owner.as_fields();
        pins.input_leaf_absorb[i] = [
            Block128::from(inp.slot_index as u128),
            Block128::from(inp.value as u128),
            owner_hi,
            owner_lo,
        ];
    }

    // Output leaf absorbs
    for j in 0..MAX_OUTPUTS.min(TXBODY_OUTPUTS) {
        let out = body
            .outputs
            .get(j)
            .copied()
            .unwrap_or_else(noid_tx::TxOutput::dummy);
        let [owner_hi, owner_lo] = out.owner.as_fields();
        pins.output_leaf_absorb[j] = [
            Block128::from(out.slot_index as u128),
            Block128::from(out.value as u128),
            owner_hi,
            owner_lo,
        ];
    }

    // Derive the body hash via native oracle
    let mut input_leaves = [[0u8; 32]; TXBODY_INPUTS];
    for i in 0..TXBODY_INPUTS {
        let inp = body
            .inputs
            .get(i)
            .cloned()
            .unwrap_or_else(noid_tx::TxInput::dummy);
        input_leaves[i] = hash_input_leaf(inp.slot_index, inp.value, &inp.owner);
    }
    let mut output_leaves = [[0u8; 32]; TXBODY_OUTPUTS];
    for j in 0..TXBODY_OUTPUTS {
        let out = body
            .outputs
            .get(j)
            .copied()
            .unwrap_or_else(noid_tx::TxOutput::dummy);
        output_leaves[j] = hash_output_leaf(out.slot_index, out.value, &out.owner);
    }

    let digest = hash_tx_body(
        &body.epoch_anchor,
        body.fee,
        &input_leaves,
        &output_leaves,
        body.is_coinbase,
    );
    let lo = u128::from_le_bytes(digest.0[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(digest.0[16..].try_into().unwrap());
    pins.tx_body_hash = [Block128::from(lo), Block128::from(hi)];

    pins
}

/// Construct a complete `TxLogicWitness` from a `TxBody`. Derives the
/// boundary pins and balance operands automatically.
///
/// # Panics
/// Panics if `body.fee > u64::MAX` — the balance circuit operates on
/// u64 operands and a fee that exceeds this range cannot be represented
/// faithfully. Well-formed transactions always have fee ≤ u64::MAX
/// (the fee leaf in the Merkle tree is also limited to u128 but the
/// balance circuit further constrains it to 64 bits).
pub fn witness_from_body(body: &TxBody) -> TxLogicWitness {
    assert!(
        body.fee <= u64::MAX as u128,
        "TxBody.fee ({}) exceeds u64::MAX — balance circuit cannot represent it",
        body.fee,
    );
    let mut balance_inputs = [0u64; 4];
    for (i, inp) in body.inputs.iter().enumerate().take(4) {
        if inp.valid {
            balance_inputs[i] = inp.value;
        }
    }
    let mut balance_outputs = [0u64; 8];
    for (j, out) in body.outputs.iter().enumerate().take(8) {
        if out.valid {
            balance_outputs[j] = out.value;
        }
    }
    let balance_fee = if body.is_coinbase { 0 } else { body.fee as u64 };

    let boundary_pins = boundary_pins_from_body(body);

    TxLogicWitness {
        body: body.clone(),
        boundary_pins,
        balance_inputs,
        balance_outputs,
        balance_fee,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
    use noid_tx::{TxInput, TxOutput};

    fn mk_balanced_body() -> TxBody {
        TxBody {
            epoch_anchor: [0xAA; 32],
            fee: 100,
            inputs: vec![
                TxInput {
                    slot_index: 7,
                    value: 1100,
                    owner: Address([0x11; 32]),
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
                    slot_index: 13,
                    value: 1000,
                    owner: Address([0x44; 32]),
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
        }
    }

    #[test]
    fn logic_air_honest_trace_accepts() {
        let body = mk_balanced_body();
        let witness = witness_from_body(&body);
        let air = TxLogicAir::new(witness.boundary_pins);
        let trace = air.build_trace(&witness);
        assert!(air.check(&trace));
    }

    #[test]
    fn logic_air_layout_matches_spine() {
        use crate::airs::tx_body_spine::spine_n_cols;
        assert_eq!(TX_LOGIC_LOG_ROWS, 11);
        assert_eq!(TX_LOGIC_N_COLS, spine_n_cols());
        let body = mk_balanced_body();
        let witness = witness_from_body(&body);
        let air = TxLogicAir::new(witness.boundary_pins);
        assert_eq!(air.n_columns(), TX_LOGIC_N_COLS);
        assert_eq!(air.log_rows(), TX_LOGIC_LOG_ROWS);
    }

    #[test]
    fn logic_air_rejects_balance_tamper() {
        let body = mk_balanced_body();
        let mut witness = witness_from_body(&body);
        witness.balance_fee = 999;
        let air = TxLogicAir::new(witness.boundary_pins);
        let trace = air.build_trace(&witness);
        assert!(!air.check(&trace));
    }

    #[test]
    fn logic_air_rejects_body_hash_tamper() {
        let body = mk_balanced_body();
        let witness = witness_from_body(&body);
        let honest_air = TxLogicAir::new(witness.boundary_pins);
        let trace = honest_air.build_trace(&witness);
        let mut pins = witness.boundary_pins;
        pins.tx_body_hash[0] += Block128::ONE;
        let tampered_air = TxLogicAir::new(pins);
        assert!(!tampered_air.check(&trace));
    }

    #[test]
    fn witness_from_body_derives_consistent_pins() {
        let body = mk_balanced_body();
        let w = witness_from_body(&body);
        assert_eq!(w.balance_inputs[0], 1100);
        assert_eq!(w.balance_outputs[0], 1000);
        assert_eq!(w.balance_fee, 100);
        assert_ne!(w.boundary_pins.tx_body_hash[0], Block128::ZERO);
    }

    #[test]
    fn coinbase_body_produces_valid_witness() {
        let body = TxBody {
            epoch_anchor: [0xBB; 32],
            fee: 0,
            inputs: vec![
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                TxOutput {
                    slot_index: 1,
                    value: 5000,
                    owner: Address([0x55; 32]),
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
            is_coinbase: true,
        };
        let witness = witness_from_body(&body);
        assert_eq!(witness.balance_fee, 0);
        assert_eq!(witness.balance_outputs[0], 5000);
        assert_ne!(witness.boundary_pins.tx_body_hash[0], Block128::ZERO);
        assert_eq!(
            witness.boundary_pins.is_coinbase_leaf[0],
            Block128::from(1u128)
        );
    }
}
