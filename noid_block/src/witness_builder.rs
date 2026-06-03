// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Helpers to build `TxBlockWitness` and `StateBindingBlockWitness` from
//! public data + wallet proof bundles — **no SpendSecret required**.
//!
//! # Security invariant
//!
//! SpendSecret never enters this module. All inputs are:
//! - `tx_body`: public (SpendSecret stripped on wire via `decode_public`)
//! - `WalletProofBundle`: proof artifacts derived from SpendSecret via
//!   one-way Poseidon2b; cannot be reversed to recover SpendSecret.
//!
//! # Witness construction
//!
//! For each transaction, the block prover needs a `TxBlockWitness`:
//!
//! ```text
//! air          ← TxLogicAir::new(boundary_pins_from_body(tx_body))
//! trace        ← TxLogicAir.build_trace(witness_from_body(tx_body))
//! pi           ← build_public_inputs(tx_body)
//! spine_inputs ← SpineInputs from boundary_pins
//! auth_public  ← extracted from bundle.logic_proof.auth
//! auth_proof   ← &bundle.logic_proof.auth
//! auth_slices  ← &bundle.auth_slices
//! ```
//!
//! The trace only uses `inp.value`, `out.value`, `fee` from the body — no
//! secret material. `witness_from_body` is a public function in `noid_air`.

use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::{Air, Trace};

use noid_core::{Block128, TowerField};
use noid_gkr::{AuthPublicInputs, SpineInputs};
use noid_stark::{prove_logic::LogicProof, WalletProofBundle};
use noid_tx::{PublicInputs, Transaction, TxBody, MAX_INPUTS, MAX_OUTPUTS};

use crate::{BlockProof, StateBindingBlockWitness, TxBlockWitness};

// ---------------------------------------------------------------------------
// Per-transaction witness from public data + bundle
// ---------------------------------------------------------------------------

/// Owned version of `TxBlockWitness` (all fields stored by value).
///
/// The borrow-based `TxBlockWitness<'a>` from `noid_block` requires lifetimes
/// tied to the original data.  `OwnedTxWitness` owns everything so it can be
/// collected into a `Vec` and then referenced.
pub struct OwnedTxWitness {
    pub air: TxLogicAir,
    pub trace: Trace,
    pub pi: PublicInputs,
    pub spine_inputs: SpineInputs,
    pub auth_public: AuthPublicInputs,
    /// Owned auth_proof (clone from bundle).
    pub auth_proof: noid_gkr::AuthProofKillShot,
    /// Owned auth_slices (clone from bundle).
    pub auth_slices: Vec<Vec<Block128>>,
}

impl OwnedTxWitness {
    /// Borrow self as a `TxBlockWitness<'_>` for passing to `prove_block`.
    pub fn as_block_witness(&self) -> TxBlockWitness<'_> {
        TxBlockWitness {
            air: &self.air as &dyn Air,
            trace: &self.trace,
            pi: &self.pi,
            spine_inputs: &self.spine_inputs,
            auth_public: &self.auth_public,
            auth_proof: &self.auth_proof,
            auth_slices: &self.auth_slices,
        }
    }
}

/// Build an `OwnedTxWitness` from a transaction's public body and its
/// wallet-provided proof bundle.
///
/// # Security
///
/// SpendSecret is NEVER used here. The trace is derived from the public
/// `tx_body` fields (slot indices, values, fee, epoch_anchor).
/// The `auth_proof` and `auth_slices` come from the bundle — they are
/// Poseidon2b outputs that cannot reveal SpendSecret.
pub fn build_tx_witness(
    tx_body: &TxBody,
    bundle: &WalletProofBundle,
    log_slots: u32,
) -> OwnedTxWitness {
    // Build the AIR from the boundary pins (all public data).
    let pins = boundary_pins_from_body(tx_body);
    let air = TxLogicAir::new(pins);

    // Build the trace from the public witness (no SpendSecret needed).
    // witness_from_body uses: inp.value, out.value, fee, epoch_anchor — all public.
    let logic_witness = witness_from_body(tx_body);
    let trace = air.build_trace(&logic_witness);

    // Build public inputs (log_slots injected by caller from block header).
    let pi = build_public_inputs(tx_body, &bundle.logic_proof, log_slots);

    // Build SpineInputs from boundary pins (all public data).
    let spine_inputs = SpineInputs {
        epoch_anchor: pins.epoch_anchor,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    };

    // Use the pre-computed AuthPublicInputs from the bundle.
    // These were produced by auth_inputs.to_public() during prove_tx,
    // so they include correct expected_address for ALL slots — including
    // dummy (valid=false) slots where the GKR circuit uses derived ZERO
    // secrets rather than zero bytes.
    let auth_public = bundle.auth_public;

    OwnedTxWitness {
        air,
        trace,
        pi,
        spine_inputs,
        auth_public,
        auth_proof: bundle.logic_proof.auth.clone(),
        auth_slices: bundle.auth_slices.clone(),
    }
}

/// Build `OwnedTxWitness` instances for all non-coinbase transactions.
///
/// Returns `(witnesses, non_cb_count)`.
/// Coinbase transactions are skipped — they have no LogicProof.
///
/// `log_slots` must match the block header's `log_slots` field so that
/// `PublicInputs.log_slots` is consistent with the chain state at inclusion
/// time. The STARK proof is cryptographically bound to this value via
/// `absorb_public_inputs`; a mismatch between pi.log_slots and
/// header.log_slots is rejected by block validation.
pub fn build_block_witnesses(
    transactions: &[Transaction],
    bundles: &[WalletProofBundle],
    log_slots: u32,
) -> Vec<OwnedTxWitness> {
    // bundles are in the same order as non-coinbase txs.
    let non_cb: Vec<_> = transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .collect();
    assert_eq!(
        non_cb.len(),
        bundles.len(),
        "one bundle per non-coinbase tx required"
    );

    non_cb
        .iter()
        .zip(bundles.iter())
        .map(|(tx, bundle)| build_tx_witness(&tx.body, bundle, log_slots))
        .collect()
}

// ---------------------------------------------------------------------------
// PublicInputs construction
// ---------------------------------------------------------------------------

fn build_public_inputs(tx_body: &TxBody, _proof: &LogicProof, log_slots: u32) -> PublicInputs {
    use noid_tx::compute_claims_commitment;

    let n_live_inputs = tx_body.inputs.iter().filter(|i| i.valid).count() as u8;
    let n_live_outputs = tx_body.outputs.iter().filter(|o| o.valid).count() as u8;
    let claims_commitment = compute_claims_commitment(&tx_body.inputs, &tx_body.outputs);

    let mut is_activation = [false; MAX_OUTPUTS];
    for (j, out) in tx_body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
        is_activation[j] = out.valid;
    }
    let mut is_deactivation = [false; MAX_INPUTS];
    for (i, inp) in tx_body.inputs.iter().enumerate().take(MAX_INPUTS) {
        is_deactivation[i] = inp.valid;
    }

    // tx_body_hash comes from the pins (public computation from body).
    let pins = boundary_pins_from_body(tx_body);
    let [lo, hi] = pins.tx_body_hash;
    let mut hash_bytes = [0u8; 32];
    hash_bytes[..16].copy_from_slice(&lo.to_u128().to_le_bytes());
    hash_bytes[16..].copy_from_slice(&hi.to_u128().to_le_bytes());

    PublicInputs {
        epoch_anchor: tx_body.epoch_anchor,
        tx_body_hash: noid_poseidon2b::primitives::TxBodyHash(hash_bytes),
        fee: tx_body.fee,
        n_live_inputs,
        n_live_outputs,
        coinbase_credit: 0,
        log_slots, // from block header — must equal header.log_slots
        claims_commitment,
        is_activation,
        is_deactivation,
    }
}

// NOTE: AuthPublicInputs is no longer reconstructed from the tx body here.
// It is stored in WalletProofBundle.auth_public by the wallet prover and
// used directly in build_tx_witness. Reconstruction from the tx body was
// incorrect for dummy (valid=false) input slots — the GKR circuit uses
// H(zero_secret) for padding, not [0;32].

// ---------------------------------------------------------------------------
// StateBindingBlockWitness — placeholder for Phase 5
// ---------------------------------------------------------------------------

/// Build `StateBindingBlockWitness` instances for `prove_block`.
///
/// # Phase 3 status
///
/// Full ZK state binding (via `BlockStateBindingAir`) is targeted for
/// Phase 5 (Integration Testing). In Phase 3, `prove_block` is called
/// with an empty state binding slice (`&[]`), which is valid — the
/// consensus layer already enforces state correctness via native
/// `validate_block_consensus`. The ZK state binding provides an
/// additional in-proof guarantee but is not required for Phase 3
/// correctness.
///
/// Phase 5 will implement the full state binding by:
/// 1. Running `BlockStateBinding::build(state, bodies, commitments)`
/// 2. Building `BlockStateBindingAir` from the opened slot data
/// 3. Building the trace columns from the opening proofs
/// 4. Passing these to `prove_block` as `state_bindings`
pub fn build_empty_state_bindings() -> Vec<StateBindingBlockWitness<'static>> {
    vec![]
}

// ---------------------------------------------------------------------------
// BlockProof → BlockReplayWitness extraction (Phase 7 recursive proof)
// ---------------------------------------------------------------------------

/// Extract a [`noid_recursive::BlockReplayWitness`] from a [`BlockProof`].
///
/// Used by the recursive proof updater in `noid_node` to advance the chain
/// proof without requiring `noid_fri_binius` as a direct dependency of the
/// node daemon.
///
/// # Field mapping
///
/// | BlockReplayWitness field      | BlockProof source                        |
/// |-------------------------------|------------------------------------------|
/// | `cap`                         | `proof.commitment.cap`                   |
/// | `state_binding_algebraics`    | `proof.state_binding_algebraics`         |
/// | `block_col_openings`          | `proof.block_col_openings`               |
/// | `block_multipoint_rounds`     | `proof.block_multipoint_rounds`          |
/// | `compact_fri`                 | `proof.mixed_opening.fri_proof`          |
/// | `mixed_all_openings`          | `proof.mixed_opening.all_openings`       |
pub fn block_proof_to_replay_witness(proof: &BlockProof) -> noid_recursive::BlockReplayWitness {
    noid_recursive::BlockReplayWitness::from_parts(
        proof.commitment.cap.clone(),
        proof.state_binding_algebraics.clone(),
        proof.block_col_openings.clone(),
        proof.block_multipoint_rounds.clone(),
        proof.mixed_opening.fri_proof.clone(),
        proof.mixed_opening.all_openings.clone(),
    )
}
