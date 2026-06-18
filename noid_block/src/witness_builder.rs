// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Helpers to build `TxBlockWitness` and `StateBindingBlockWitness` from
//! public data + wallet proof bundles — **no SpendSecret required**.
//!
//! # Security invariant
//!
//! SpendSecret never enters this module. All inputs are:
//! - `tx_body`: public (SpendSecret stripped on wire via `decode_public`)
//! - `WalletProofBundle`: wallet proof artifacts derived from SpendSecret.
//!   These are not raw secrets and are covered by the SC-5 one-wayness model.
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
//! auth_public  ← extracted from Standard4x8 bundle
//! auth_proof   ← extracted from Standard4x8 bundle.logic_proof.auth
//! auth_slices  ← extracted from Standard4x8 bundle.auth_slices
//! ```
//!
//! The trace only uses `inp.value`, `out.value`, `fee` from the body — no
//! secret material. `witness_from_body` is a public function in `noid_air`.

use std::collections::HashMap;

use noid_air::airs::block_state_binding::{
    BlockStateBindingAir, BlockStateBindingClaim, BlockStateBindingWitness,
};
use noid_air::composition::sweep_logic_air_and_trace_from_body;
use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::composition::SweepTxLogicAir;
use noid_air::{Air, Trace};
use noid_chain::consensus::params::LOG_SEGMENT_SIZE;
use noid_chain::segmented_state::SegmentColumns;
use noid_chain::state_binding::BlockStateBinding;
use noid_core::mle::evaluate_slice;
use noid_core::{Block128, TowerField};
use noid_fri::Channel;
use noid_gkr::{AuthPublicInputs, SpineInputs, SweepAuthPublicInputs, SweepSpineInputs};
use noid_stark::prove_logic_sweep::{
    sweep_spine_inputs_from_body, N_SWEEP_AUTH_SLICES, SWEEP_BOUNDARY_BASE_LOG,
};
use noid_stark::WalletProofBundle;
use noid_tx::{PublicInputs, Transaction, TxBody, TxShape, MAX_INPUTS, MAX_OUTPUTS};

use crate::{BlockProof, StateBindingBlockWitness, TxBlockWitness};

// ---------------------------------------------------------------------------
// Per-transaction witness from public data + bundle
// ---------------------------------------------------------------------------

/// Owned standard witness (all fields stored by value).
pub struct OwnedStandardTxWitness {
    /// Index into `Block.transactions`.
    pub block_tx_index: u32,
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

/// Owned sweep witness.  This is not block-provable until `SweepBucketProof`
/// lands, but constructing it here removes the standard-only witness-builder
/// assumption and keeps all data public/no-secret.
pub struct OwnedSweepTxWitness {
    /// Index into `Block.transactions`.
    pub block_tx_index: u32,
    pub air: SweepTxLogicAir,
    pub trace: Trace,
    pub pi: PublicInputs,
    pub spine_inputs: SweepSpineInputs,
    pub auth_public: SweepAuthPublicInputs,
    /// Owned sweep AuthGKR proof cloned from the wallet logic proof.
    pub auth_proof: noid_gkr::SweepAuthProofKillShot,
    /// Owned sweep AuthGKR `state` slices, mirroring standard `auth_slices`.
    pub auth_slices: Vec<Vec<Block128>>,
}

/// Shape-dispatched owned transaction witness.
pub enum OwnedTxWitness {
    Standard4x8(OwnedStandardTxWitness),
    Sweep25x2(OwnedSweepTxWitness),
}

impl OwnedTxWitness {
    pub fn shape(&self) -> TxShape {
        match self {
            Self::Standard4x8(_) => TxShape::Standard4x8,
            Self::Sweep25x2(_) => TxShape::Sweep25x2,
        }
    }

    pub fn block_tx_index(&self) -> u32 {
        match self {
            Self::Standard4x8(w) => w.block_tx_index,
            Self::Sweep25x2(w) => w.block_tx_index,
        }
    }

    /// Borrow self as a standard `TxBlockWitness<'_>` for the current standard
    /// bucket prover. Sweep witnesses require the Phase N5 sweep bucket prover.
    pub fn as_block_witness(&self) -> TxBlockWitness<'_> {
        match self {
            Self::Standard4x8(w) => TxBlockWitness {
                block_tx_index: w.block_tx_index,
                air: &w.air as &dyn Air,
                trace: &w.trace,
                pi: &w.pi,
                spine_inputs: &w.spine_inputs,
                auth_public: &w.auth_public,
                auth_proof: &w.auth_proof,
                auth_slices: &w.auth_slices,
            },
            Self::Sweep25x2(_) => {
                panic!("Sweep25x2 witness requires SweepBucketProof; miner must keep filtering sweep until Phase N5")
            }
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
/// The `auth_proof` and `auth_slices` come from the bundle. They are
/// proof artifacts, not raw `SpendSecret`; SC-5 covers their one-wayness model.
pub fn build_tx_witness(
    block_tx_index: u32,
    tx_body: &TxBody,
    bundle: &WalletProofBundle,
    log_slots: u32,
) -> OwnedTxWitness {
    assert_eq!(
        bundle.shape(),
        tx_body.shape,
        "wallet proof bundle shape does not match tx body shape"
    );
    match bundle {
        WalletProofBundle::Standard4x8(bundle) => {
            // Build the AIR from the boundary pins (all public data).
            let pins = boundary_pins_from_body(tx_body);
            let air = TxLogicAir::new(pins);

            // Build the trace from the public witness (no SpendSecret needed).
            // witness_from_body uses: inp.value, out.value, fee, epoch_anchor — all public.
            let logic_witness = witness_from_body(tx_body);
            let trace = air.build_trace(&logic_witness);

            // Build public inputs (log_slots injected by caller from block header).
            let pi = build_public_inputs(tx_body, log_slots);

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

            OwnedTxWitness::Standard4x8(OwnedStandardTxWitness {
                block_tx_index,
                air,
                trace,
                pi,
                spine_inputs,
                auth_public,
                auth_proof: bundle.logic_proof.auth.clone(),
                auth_slices: bundle.auth_slices.clone(),
            })
        }
        WalletProofBundle::Sweep25x2(bundle) => {
            assert_eq!(
                bundle.auth_slices.len(),
                N_SWEEP_AUTH_SLICES,
                "malformed Sweep25x2 auth_slices count"
            );
            assert!(
                bundle
                    .auth_slices
                    .iter()
                    .all(|slice| slice.len() == (1usize << SWEEP_BOUNDARY_BASE_LOG)),
                "malformed Sweep25x2 auth_slices length"
            );

            let (air, trace) = sweep_logic_air_and_trace_from_body(tx_body);
            let pi = build_public_inputs(tx_body, log_slots);
            let spine_inputs = sweep_spine_inputs_from_body(tx_body);

            OwnedTxWitness::Sweep25x2(OwnedSweepTxWitness {
                block_tx_index,
                air,
                trace,
                pi,
                spine_inputs,
                auth_public: bundle.auth_public,
                auth_proof: bundle.logic_proof.auth.clone(),
                auth_slices: bundle.auth_slices.clone(),
            })
        }
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
        .enumerate()
        .filter(|(_, tx)| !tx.body.is_coinbase)
        .collect();
    assert_eq!(
        non_cb.len(),
        bundles.len(),
        "one bundle per non-coinbase tx required"
    );

    non_cb
        .into_iter()
        .zip(bundles.iter())
        .map(|((block_tx_index, tx), bundle)| {
            build_tx_witness(block_tx_index as u32, &tx.body, bundle, log_slots)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// PublicInputs construction
// ---------------------------------------------------------------------------

fn build_public_inputs(tx_body: &TxBody, log_slots: u32) -> PublicInputs {
    use noid_tx::{compute_claims_commitment, hash_tx_body_for_shape};

    let n_live_inputs = tx_body.inputs.iter().filter(|i| i.valid).count() as u8;
    let n_live_outputs = tx_body.outputs.iter().filter(|o| o.valid).count() as u8;
    let claims_commitment = compute_claims_commitment(&tx_body.inputs, &tx_body.outputs);

    let mut is_activation = [false; MAX_OUTPUTS];
    let mut is_deactivation = [false; MAX_INPUTS];
    if tx_body.shape == TxShape::Standard4x8 {
        for (j, out) in tx_body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
            is_activation[j] = out.valid;
        }
        for (i, inp) in tx_body.inputs.iter().enumerate().take(MAX_INPUTS) {
            is_deactivation[i] = inp.valid;
        }
    }

    PublicInputs {
        epoch_anchor: tx_body.epoch_anchor,
        tx_body_hash: hash_tx_body_for_shape(
            tx_body.shape,
            &tx_body.epoch_anchor,
            tx_body.fee,
            &tx_body.inputs,
            &tx_body.outputs,
            tx_body.is_coinbase,
        ),
        shape_id: tx_body.shape.id(),
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
    /// Pre-state segment columns (owned; for FRI opening in `prove_block`).
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
            columns: &self.columns,
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
    coinbase_body: Option<&noid_tx::TxBody>,
    pre_segs: &HashMap<u16, SegmentColumns>,
    prev_state_root: [u8; 32],
    n_tx: u32,
    log_slots: u32,
) -> Vec<OwnedStateBindingWitness> {
    let eff_log = (log_slots as usize).min(LOG_SEGMENT_SIZE as usize);
    let seg_mask = (1u32 << eff_log) - 1;

    // Group claims by segment.
    let mut seg_claims: HashMap<u16, Vec<BlockStateBindingClaim>> = HashMap::new();

    // Include coinbase output mints so post-state MLE and seg_root are consistent
    // with the global new_state_root (which includes coinbase changes).
    if let Some(cb) = coinbase_body {
        for out in cb.outputs.iter().filter(|o| o.valid) {
            let seg_id = (out.slot_index >> eff_log) as u16;
            let local = out.slot_index & seg_mask;
            let [owner_hi, owner_lo] = out.owner.as_fields();
            seg_claims
                .entry(seg_id)
                .or_default()
                .push(BlockStateBindingClaim::mint(
                    local,
                    noid_core::Block128::from(out.value as u128),
                    owner_hi,
                    owner_lo,
                ));
        }
    }

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
            // Pre-state for mint outputs is always zero by invariant; advance
            // iterator in lockstep with outputs but discard the value.
            let _ = out_iter.next();
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

        // Pre-state MLE evaluation. Allocate a zero segment only for genuinely
        // absent pre-state segments; production hot paths usually provide one.
        let pre_cols_owned = pre_segs
            .get(&seg_id)
            .cloned()
            .unwrap_or_else(|| SegmentColumns::new_zero(seg_size));
        let prev_lane_openings = [
            mle_eval(&pre_cols_owned.values, &eval_point),
            mle_eval(&pre_cols_owned.owners_hi, &eval_point),
            mle_eval(&pre_cols_owned.owners_lo, &eval_point),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayWitnessError {
    /// The current recursive AIR can replay only buckets that carry a real
    /// block-level multipoint transcript. Blocks with no replayable bucket stay
    /// fail-closed.
    MissingReplayableBucket,
    /// Reserved for future cases where a bucket is present but cannot be mapped
    /// into the recursive replay relation.
    UnsupportedBucketLayout,
}

/// Extract a [`noid_recursive::BlockReplayWitness`] from a bucketized
/// [`BlockProof`].
///
/// Used by the recursive proof updater in `noid_node` to advance the chain
/// proof without requiring `noid_fri_binius` as a direct dependency of the
/// node daemon.
///
/// Security: this accepts standard-only, sweep-only, and mixed proofs. Mixed
/// proofs map the standard bucket to the primary recursive lane and the sweep
/// bucket to the secondary recursive lane, so recursion does not drop either
/// bucket while relying on the canonical hash for the other.
///
/// # Field mapping
///
/// | BlockReplayWitness field      | BlockProof source                                      |
/// |-------------------------------|--------------------------------------------------------|
/// | `cap`                         | primary bucket `commitment.cap`                        |
/// | `state_binding_algebraics`    | `proof.state_binding_algebraics`                       |
/// | `block_col_openings`          | primary bucket `block_col_openings`                    |
/// | `block_multipoint_rounds`     | primary bucket `block_multipoint_rounds`               |
/// | `block_multipoint_challenges` | primary bucket `block_multipoint_challenges`           |
/// | secondary block fields        | secondary bucket transcript, or zero for single bucket |
/// | `compact_fri`                 | primary bucket `mixed_opening.fri_proof`               |
/// | `mixed_all_openings`          | primary bucket `mixed_opening.all_openings`            |
/// | `block_initial_claim`         | primary bucket `block_initial_claim`                   |
/// | `chain_claim`                 | `block_recursive_claim_field(proof)`                   |
pub fn block_proof_to_replay_witness(
    proof: &BlockProof,
) -> Result<noid_recursive::BlockReplayWitness, ReplayWitnessError> {
    match (proof.standard_bucket.as_ref(), proof.sweep_bucket.as_ref()) {
        (Some(standard), Some(sweep)) => {
            Ok(noid_recursive::BlockReplayWitness::from_two_bucket_parts(
                standard.commitment.cap.clone(),
                proof.state_binding_algebraics.clone(),
                standard.block_col_openings.clone(),
                standard.block_multipoint_rounds.clone(),
                standard.block_multipoint_challenges.clone(),
                sweep.block_multipoint_rounds.clone(),
                sweep.block_multipoint_challenges.clone(),
                sweep.block_initial_claim,
                standard.mixed_opening.fri_proof.clone(),
                standard.mixed_opening.all_openings.clone(),
                standard.block_initial_claim,
                crate::block_recursive_claim_field(proof),
            ))
        }
        (Some(bucket), None) => Ok(noid_recursive::BlockReplayWitness::from_parts(
            bucket.commitment.cap.clone(),
            proof.state_binding_algebraics.clone(),
            bucket.block_col_openings.clone(),
            bucket.block_multipoint_rounds.clone(),
            bucket.block_multipoint_challenges.clone(),
            bucket.mixed_opening.fri_proof.clone(),
            bucket.mixed_opening.all_openings.clone(),
            bucket.block_initial_claim,
            crate::block_recursive_claim_field(proof),
        )),
        (None, Some(bucket)) => Ok(noid_recursive::BlockReplayWitness::from_parts(
            bucket.commitment.cap.clone(),
            proof.state_binding_algebraics.clone(),
            bucket.block_col_openings.clone(),
            bucket.block_multipoint_rounds.clone(),
            bucket.block_multipoint_challenges.clone(),
            bucket.mixed_opening.fri_proof.clone(),
            bucket.mixed_opening.all_openings.clone(),
            bucket.block_initial_claim,
            crate::block_recursive_claim_field(proof),
        )),
        (None, None) => Err(ReplayWitnessError::MissingReplayableBucket),
    }
}
