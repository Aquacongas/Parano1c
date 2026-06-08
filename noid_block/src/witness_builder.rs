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

use std::collections::HashMap;

use noid_air::airs::block_state_binding::{
    BlockStateBindingAir, BlockStateBindingClaim, BlockStateBindingWitness,
};
use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::{Air, Trace};
use noid_chain::consensus::params::LOG_SEGMENT_SIZE;
use noid_chain::segmented_state::SegmentColumns;
use noid_chain::state_binding::BlockStateBinding;
use noid_core::mle::evaluate_slice;
use noid_core::{Block128, TowerField};
use noid_fri::Channel;
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
// StateBindingBlockWitness
// ---------------------------------------------------------------------------

/// Owned state binding witness for one dirty segment.
pub struct OwnedStateBindingWitness {
    pub air: BlockStateBindingAir,
    pub columns: Vec<Vec<Block128>>,
    pub seg_id: u16,
    /// Pre-state segment columns (owned; for FRI opening in prove_block Stage 5c).
    pub pre_cols: SegmentColumns,
    /// Claims (spend/mint) for this segment; used to derive post-state columns.
    pub claims: Vec<BlockStateBindingClaim>,
    /// Merkle siblings for pre-state seg_root → prev_state_root.
    pub pre_siblings: Vec<[u8; 32]>,
    /// Merkle siblings for post-state seg_root → new_state_root.
    pub post_siblings: Vec<[u8; 32]>,
    /// Merkle tree depth. 0 = single-segment (no path needed).
    pub tree_depth: usize,
    /// Block's new state root (from binding.new_state_root).
    pub new_state_root: [u8; 32],
}

impl OwnedStateBindingWitness {
    pub fn as_witness(&self) -> StateBindingBlockWitness<'_> {
        StateBindingBlockWitness {
            air: &self.air,
            columns: self.columns.clone(),
            seg_id: self.seg_id,
            pre_cols: Some(&self.pre_cols),
            claims: &self.claims,
            pre_siblings: &self.pre_siblings,
            post_siblings: &self.post_siblings,
            tree_depth: self.tree_depth,
            new_state_root: self.new_state_root,
        }
    }
}

/// Evaluate MLE of `vals` at `point`.
#[inline]
fn mle_eval(vals: &[Block128], point: &[Block128]) -> Block128 {
    evaluate_slice(vals, point)
}

/// Build one `OwnedStateBindingWitness` per dirty segment.
///
/// # Parameters
/// - `binding` — slot openings from `BlockStateBinding` (built in `build_block_template`)
/// - `bodies` — non-coinbase tx bodies in block order
/// - `pre_segs` — pre-state segment columns keyed by seg_id
/// - `prev_state_root` — for Fiat-Shamir channel seeding
/// - `n_tx` — number of non-coinbase txs
/// - `log_slots` — chain log_slots value
pub fn build_state_bindings_from_binding(
    binding: &BlockStateBinding,
    bodies: &[noid_tx::TxBody],
    pre_segs: &HashMap<u16, SegmentColumns>,
    prev_state_root: [u8; 32],
    n_tx: u32,
    log_slots: u32,
) -> Vec<OwnedStateBindingWitness> {
    let eff_log = (log_slots as usize).min(LOG_SEGMENT_SIZE as usize);
    let seg_mask = (1u32 << eff_log) - 1;

    // Group claims by segment.
    let mut seg_claims: HashMap<u16, Vec<BlockStateBindingClaim>> = HashMap::new();
    for (body, opening) in bodies.iter().zip(binding.tx_openings.iter()) {
        let mut inp_iter = opening.input_openings.iter();
        for inp in body.inputs.iter().filter(|i| i.valid) {
            let sv = inp_iter.next().expect("input opening mismatch");
            let seg_id = (inp.slot_index >> eff_log) as u16;
            let local = inp.slot_index & seg_mask;
            seg_claims
                .entry(seg_id)
                .or_default()
                .push(BlockStateBindingClaim::spend(
                    local,
                    sv.value,
                    sv.owner_hi,
                    sv.owner_lo,
                ));
        }
        let mut out_iter = opening.output_openings.iter();
        for out in body.outputs.iter().filter(|o| o.valid) {
            let _pre = out_iter.next();
            let seg_id = (out.slot_index >> eff_log) as u16;
            let local = out.slot_index & seg_mask;
            let [owner_hi, owner_lo] = out.owner.as_fields();
            seg_claims
                .entry(seg_id)
                .or_default()
                .push(BlockStateBindingClaim::mint(
                    local,
                    Block128::from(out.value as u128),
                    owner_hi,
                    owner_lo,
                ));
        }
    }

    // Sort by seg_id for deterministic eval_point derivation.
    let mut sorted: Vec<(u16, Vec<BlockStateBindingClaim>)> = seg_claims.into_iter().collect();
    sorted.sort_unstable_by_key(|(sid, _)| *sid);

    let seg_size = 1usize << eff_log;
    let mut result = Vec::with_capacity(sorted.len());

    for (sb_idx, (seg_id, claims)) in sorted.into_iter().enumerate() {
        // Derive eval_point and gamma from deterministic channel.
        let mut ch = Channel::new();
        let lo = u128::from_le_bytes(prev_state_root[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(prev_state_root[16..].try_into().unwrap());
        ch.observe_field_elem(Block128::from(lo));
        ch.observe_field_elem(Block128::from(hi));
        ch.observe_field_elem(Block128::from((n_tx as u128) + sb_idx as u128));
        let eval_point: Vec<Block128> = (0..eff_log).map(|_| ch.get_random_point()).collect();
        let gamma = ch.get_random_point();

        // Pre-state MLE evaluation.
        let zero_cols = SegmentColumns::new_zero(seg_size);
        let pre_ref = pre_segs.get(&seg_id).unwrap_or(&zero_cols);
        let pre_cols_owned = pre_ref.clone();
        let prev_lane_openings = [
            mle_eval(&pre_ref.values, &eval_point),
            mle_eval(&pre_ref.owners_hi, &eval_point),
            mle_eval(&pre_ref.owners_lo, &eval_point),
        ];

        // Build witness and compute new_lane_openings.
        let mut witness = BlockStateBindingWitness::new(
            claims.clone(),
            eval_point.clone(),
            gamma,
            prev_lane_openings,
            [Block128::ZERO; 3],
        );
        let new_lane_openings = witness.expected_new_lane_openings(prev_lane_openings);
        witness.new_lane_openings = new_lane_openings;

        let expected_batched = witness.expected_batched_claims();
        let air = BlockStateBindingAir::new(
            &claims,
            prev_lane_openings,
            new_lane_openings,
            &eval_point,
            gamma,
            expected_batched,
        );
        let columns = air.build_trace(&witness);

        // Extract siblings for this segment from the binding.
        let pre_siblings = binding
            .pre_seg_siblings
            .get(&seg_id)
            .cloned()
            .unwrap_or_default();
        let post_siblings = binding
            .post_seg_siblings
            .get(&seg_id)
            .cloned()
            .unwrap_or_default();

        result.push(OwnedStateBindingWitness {
            air,
            columns,
            seg_id,
            pre_cols: pre_cols_owned,
            claims,
            pre_siblings,
            post_siblings,
            tree_depth: binding.tree_depth,
            new_state_root: binding.new_state_root,
        });
    }
    result
}

/// Build empty state bindings (coinbase-only or bench mode).
pub fn build_empty_state_bindings() -> Vec<StateBindingBlockWitness<'static>> {
    vec![]
}

// ---------------------------------------------------------------------------
// BlockProof → BlockReplayWitness extraction (recursive chain proof)
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
        proof.block_initial_claim,
    )
}
