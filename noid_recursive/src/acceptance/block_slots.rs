// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The block-slot assembly: ONE accepted block's component verification
//! replayed inside a FieldR1cs trace.
//!
//! Trace twin of `block_certificate_backend::
//! verify_accepted_block_batch_components` for a single-block batch: every
//! component killshot runs through its existing slot builder, and the
//! cross-component equalities — which the native path gets for free by
//! deriving every component input from the same block objects — become
//! explicit wire sharing and equality pins:
//!
//! - the accepted-claim transcript's child-header section is pinned
//!   field-for-field to the header-hash killshot statement (the claim
//!   transcript embeds `AcceptedBlockHeaderClaim::from_header(header)`);
//! - the claim's parent-section block id is the header's `prev_block_hash`,
//!   its parent state root / height are the start accumulator's;
//! - the accumulator fold, the chain-accumulator killshot items and the
//!   claim-hash statement share the `expected_claim` / `block_id` wires
//!   (the image of `chain_accumulator_proof_inputs` deriving both from one
//!   witness);
//! - `validate_accumulator_boundary`: first block height = start height + 1
//!   (affine pin), end accumulator pins live in the claim-fold slot;
//! - every tx-root Merkle path pins its root to the header `tx_root`, its
//!   leaf to the spine slot's tx-body hash, its direction bits to the
//!   CONSTANT bits of its tx position, and the last real path pins its
//!   right-hand siblings to the canonical zero-subtree digests (the padding
//!   rim the native root reconstruction binds);
//! - each owner-auth slot pins its `tx_body_hash` to the spine hash of its
//!   tx and discharges its wallet-PCS obligation; the authorization totals
//!   are pinned to the per-slot counts AND to the claim's resource fields;
//! - the exact-state composite roots pin to the claim's parent/child state
//!   roots and `log_slots` lanes.
//!
//! NOT bound here (audited residue, each correctly scoped to another
//! layer, none a hole in what this file claims):
//! - exact-state INTERNAL wiring (slot leaves ↔ state paths ↔ utxo/guard
//!   roots): each of the five killshots self-binds its own hash chain, but
//!   the cross-killshot gluing (state-path root == composite utxo_root, and
//!   likewise for guard) is a free witness pair here — natively guaranteed
//!   by `derive_exact_state_killshot_inputs` re-deriving every input from
//!   the one validated block. Lands with the region layer's per-tx algebra.
//! - public transaction logic — likewise a region-layer per-tx obligation.
//! - the parent header's `active_slot_count` / `alloc_counter` (they feed
//!   only the claim hash and there is no accumulator wire to pin them
//!   against): these are consensus-continuity lanes the LINK binds by
//!   exposing the previous link's child consensus. Header PoW/ASERT/MTP
//!   fields (timestamp, miner, nonce, target) are deliberately out of π's
//!   scope — a fresh peer validates its own header chain.
//! - the wallet-capsule PCS opening: replayed by `discharge_auth_pcs_
//!   obligation` when [`BlockSlotsConfig::discharge_wallet_pcs`] is set, but
//!   its trace STRUCTURE is proof-dependent (compact-FRI query positions /
//!   Merkle schedule), so it is the SOLE obstacle to a fixed class matrix
//!   across different blocks — everything else here is already class-fixed.
//!   Its class-fixed form is a region-layer ([G]) obligation.
//!
//! A proof assembled from these slots binds the block's hashing work and
//! the full statement skeleton; the transition-semantics gluing and the
//! shape-fixed wallet-PCS are the region-layer remainder.

use noid_core::Block128;
use noid_gkr::merkle_circuit::MerkleCircuit;
use noid_poseidon2b::native::compression::compress;

use super::trace::accepted_claim_batch::{
    build_accepted_claim_batch_claim_slot, digest_lanes, AccumulatorWires, ClaimBatchStepWires,
};
use super::trace::accepted_claim_hash::{build_accepted_claim_hash_slot, AcceptedClaimHashInputsTrace};
use super::trace::auth_pcs::discharge_auth_pcs_obligation;
use super::trace::region_source_binding::{
    discharge_auth_pcs_obligations_via_region, RegionDischargeParams, RegionPcsClaim,
};
use super::trace::checkpoint_poseidon::{
    build_checkpoint_poseidon_slot_with_inputs, ChainAccumulatorBatchInputsTrace,
    ChainAccumulatorItemTrace, HeaderHashInputsTrace,
};
use super::trace::exact_state::{build_exact_state_slot, ExactStateSlotWires};
use super::trace::merkle_path::{build_batched_merkle_slot, MerklePathInputsTrace};
use super::trace::owner_auth::{build_owner_auth_slot, OwnerAuthPublicInputsTrace};
use super::trace::tx_body_spine::{build_standard_tx_body_slot, SpineInputsTrace};
use super::trace::{
    alloc_block, const_block, flat_const, mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder,
    LinExpr, RawChannelTrace, F128,
};
use crate::accumulator::ChainAccumulator;
use crate::block_certificate_backend::{
    AcceptedBlockBatchComponentInputs, AcceptedBlockBatchComponentProof,
};
use crate::pow_header::header_hash_proof_inputs;

// ---------------------------------------------------------------------------
// Fixed field positions (protocol constants of the two statement encodings)
// ---------------------------------------------------------------------------

/// Offsets inside one header-claim section of the accepted-block claim
/// transcript (`push_header_claim_fields` order).
pub mod header_claim {
    pub const BLOCK_ID: usize = 0; // 2 lanes
    pub const PREV_BLOCK_HASH: usize = 2; // 2
    pub const STATE_ROOT: usize = 4; // 2
    pub const TX_ROOT: usize = 6; // 2
    pub const TIMESTAMP: usize = 8;
    pub const HEIGHT: usize = 9;
    pub const MINER: usize = 10; // 2
    pub const NONCE: usize = 12;
    pub const TARGET: usize = 13; // 2
    pub const LOG_SLOTS: usize = 15;
    pub const ACTIVE_SLOT_COUNT: usize = 16;
    pub const ALLOC_COUNTER: usize = 17;
    pub const FIELDS: usize = 18;
}

/// Absolute lane positions inside the 80-field accepted-block claim
/// transcript (`accepted_block_claim_fields_from_transcript` order). The
/// window sizes are the consensus constants; the layout is cross-checked
/// against the native encoder by a sentinel test on the noid_block side.
pub mod claim_layout {
    use noid_chain::consensus::params::{EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS};

    pub const BLOCK_SECTION: usize = 0;
    pub const PARENT_SECTION: usize = super::header_claim::FIELDS;
    pub const TIMESTAMPS_WINDOW: usize = PARENT_SECTION + super::header_claim::FIELDS;
    pub const ACTIVE_COUNTS_WINDOW: usize = TIMESTAMPS_WINDOW + 1 + MEDIAN_TIME_BLOCKS;
    pub const ANCHOR_HEIGHT: usize = ACTIVE_COUNTS_WINDOW + 1 + EXPANSION_WINDOW as usize;
    pub const ANCHOR_TIMESTAMP: usize = ANCHOR_HEIGHT + 1;
    pub const ANCHOR_TARGET: usize = ANCHOR_TIMESTAMP + 1; // 2 lanes
    pub const BLOCK_BODY_LEN: usize = ANCHOR_TARGET + 2;
    pub const BLOCK_PROOF_LEN: usize = BLOCK_BODY_LEN + 1;
    pub const AUTH_SIDECAR_LEN: usize = BLOCK_PROOF_LEN + 1;
    pub const TX_COUNT: usize = AUTH_SIDECAR_LEN + 1;
    pub const USER_TX_COUNT: usize = TX_COUNT + 1;
    pub const LIVE_INPUT_COUNT: usize = USER_TX_COUNT + 1;
    pub const OUTPUT_COUNT: usize = LIVE_INPUT_COUNT + 1;
    pub const STATE_FRONTIER_NODE_COUNT: usize = OUTPUT_COUNT + 1;
    pub const FIELDS: usize = STATE_FRONTIER_NODE_COUNT + 2;
}

/// Offsets inside the 16-field PoW header schedule
/// (`pow_header_fields_into` order — the header-hash killshot statement).
pub mod header_fields {
    pub const PREV_BLOCK_HASH: usize = 0; // 2 lanes
    pub const STATE_ROOT: usize = 2; // 2
    pub const TX_ROOT: usize = 4; // 2
    pub const TIMESTAMP: usize = 6;
    pub const HEIGHT: usize = 7;
    pub const MINER: usize = 8; // 2
    pub const NONCE: usize = 10;
    pub const TARGET: usize = 11; // 2
    pub const LOG_SLOTS: usize = 13;
    pub const ACTIVE_SLOT_COUNT: usize = 14;
    pub const ALLOC_COUNTER: usize = 15;
    pub const FIELDS: usize = 16;
}

const _: () = assert!(claim_layout::FIELDS == noid_gkr::accepted_claim_killshot::ACCEPTED_CLAIM_FIELDS);
const _: () = assert!(header_fields::FIELDS == noid_chain::consensus::pow::POW_HEADER_FIELD_COUNT);

fn pin_eq2(b: &mut FieldR1csBuilder, a: &[LinExpr; 2], c: &[LinExpr; 2]) {
    pin_eq(b, &a[0], &c[0]);
    pin_eq(b, &a[1], &c[1]);
}

/// Pin `child == parent + 1` as u64 INTEGERS (not field/XOR): a
/// ripple-carry increment over the tower-bit decomposition of `parent`.
/// In char 2 the field ops ARE the bit ops — `bit_i XOR carry_i` is
/// `+`, `bit_i AND carry_i` is `*` — so the incrementer is exact and the
/// no-overflow guard pins the final carry to zero.
fn pin_u64_successor(b: &mut FieldR1csBuilder, parent: &LinExpr, child: &LinExpr) {
    const N: usize = 64;
    let parent_bits = range_check_bits(b, parent, N);
    let mut carry = LinExpr::constant(F128::ONE);
    let mut recon = LinExpr::zero();
    let mut terms: Vec<LinExpr> = Vec::with_capacity(N);
    for (i, &bit) in parent_bits.iter().enumerate() {
        let p_i = LinExpr::from_wire(bit);
        // child_i = p_i XOR carry_i.
        let child_i = p_i.add(&carry);
        terms.push(child_i.scale(flat_const(1u128 << i)));
        // carry_{i+1} = p_i AND carry_i.
        carry = mul(b, &p_i, &carry);
    }
    // Assemble the reconstruction once (avoid the quadratic add loop).
    for t in &terms {
        recon = recon.add(t);
    }
    // No u64 overflow: the successor stays in range.
    pin_zero(b, &carry);
    pin_eq(b, child, &recon);
}

fn pin_pair_at(b: &mut FieldR1csBuilder, fields: &[LinExpr], at: usize, to: &[LinExpr; 2]) {
    pin_eq(b, &fields[at], &to[0]);
    pin_eq(b, &fields[at + 1], &to[1]);
}

/// Canonical zero-subtree digest lanes per level: `Z_0 = zero leaf`,
/// `Z_{L+1} = compress(Z_L, Z_L)` — the tx-tree padding constants the last
/// real path's right-hand siblings must equal.
fn zero_subtree_lanes(depth: usize) -> Vec<[Block128; 2]> {
    let mut out = Vec::with_capacity(depth);
    let mut z = [0u8; 32];
    for _ in 0..depth {
        out.push(digest_lanes(&z));
        z = compress(&z, &z);
    }
    out
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// The primary statement wires of one assembled block, returned for the
/// link-level bindings (IO exposure and cross-link chain pins).
pub struct BlockSlots {
    /// The header-hash killshot statement — THE header wire set every other
    /// slot is pinned against.
    pub header: HeaderHashInputsTrace,
    /// The 80 accepted-block claim transcript lanes.
    pub claim: AcceptedClaimHashInputsTrace,
    pub start_acc: AccumulatorWires,
    pub end_acc: AccumulatorWires,
    pub spine_inputs: Vec<SpineInputsTrace>,
    pub tx_hashes: Vec<[LinExpr; 2]>,
    pub tx_root_paths: Vec<MerklePathInputsTrace>,
    pub auth_inputs: Vec<OwnerAuthPublicInputsTrace>,
    pub exact_state: ExactStateSlotWires,
    /// Committed-column opening claims emitted by the region wallet-PCS
    /// discharge (empty unless `BlockSlotsConfig::wallet_pcs_region` was set).
    /// The link threads these into its public-IO (`spec.claims` + `io`).
    pub pending_wallet_pcs: Vec<RegionPcsClaim>,
}

impl BlockSlots {
    /// The receipt↔projection lanes in `verify_acceptance_against_projection`
    /// order: height, block_id, parent_block_id, child_state_root, tx_root,
    /// child_log_slots, child_active_slot_count, child_alloc_counter.
    pub fn projection_lanes(&self) -> [LinExpr; 12] {
        let f = &self.header.fields;
        [
            f[header_fields::HEIGHT].clone(),
            self.header.expected_block_id[0].clone(),
            self.header.expected_block_id[1].clone(),
            f[header_fields::PREV_BLOCK_HASH].clone(),
            f[header_fields::PREV_BLOCK_HASH + 1].clone(),
            f[header_fields::STATE_ROOT].clone(),
            f[header_fields::STATE_ROOT + 1].clone(),
            f[header_fields::TX_ROOT].clone(),
            f[header_fields::TX_ROOT + 1].clone(),
            f[header_fields::LOG_SLOTS].clone(),
            f[header_fields::ACTIVE_SLOT_COUNT].clone(),
            f[header_fields::ALLOC_COUNTER].clone(),
        ]
    }
}

/// Assembly options.
#[derive(Clone, Copy, Debug)]
pub struct BlockSlotsConfig {
    /// Replay the wallet-capsule PCS opening in-trace (the compact-FRI
    /// `discharge_auth_pcs_obligation`). This is the ONE component whose
    /// trace STRUCTURE is proof-dependent (query positions / Merkle
    /// schedule), so it is the sole obstacle to a fixed class matrix
    /// across different blocks and the region layer's replacement target.
    /// With it off, the owner-auth GKR statement is still replayed but its
    /// reduced PCS claim is left undischarged — for shape experiments and
    /// the region-layer transition, never for a complete proof.
    pub discharge_wallet_pcs: bool,
    /// When `Some`, discharge the wallet-PCS via the SHAPE-FIXED region layer
    /// (`discharge_auth_pcs_obligation_via_region`) instead of the inline
    /// compact-FRI replay. The region discharge is class-fixed (its trace
    /// structure does NOT drift with the proof), and it emits committed-column
    /// opening claims collected into [`BlockSlots::pending_wallet_pcs`] for the
    /// link to thread through public-IO. `None` = the inline discharge. Only
    /// consulted when `discharge_wallet_pcs` is true.
    pub wallet_pcs_region: Option<RegionDischargeParams>,
}

impl Default for BlockSlotsConfig {
    fn default() -> Self {
        Self {
            discharge_wallet_pcs: true,
            wallet_pcs_region: None,
        }
    }
}

/// Assemble the single-block component replay. `inputs`/`proof` are the
/// native component objects; `start/end_accumulator` the block's
/// accumulator boundary. The current class shape is a pure-standard tier
/// (sweep component empty); the sweep arm lands with its tier class.
pub fn build_block_slots(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> BlockSlots {
    build_block_slots_with_config(
        b,
        start_accumulator,
        end_accumulator,
        inputs,
        proof,
        BlockSlotsConfig::default(),
    )
}

/// [`build_block_slots`] with explicit assembly options.
pub fn build_block_slots_with_config(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
    config: BlockSlotsConfig,
) -> BlockSlots {
    // validate_component_shape + the single-block batch shape, as asserts.
    let witness = &inputs.accepted_claim_witness;
    assert_eq!(witness.headers.len(), 1, "one block per link");
    assert_eq!(witness.accepted_block_claims.len(), 1);
    assert_eq!(inputs.accepted_claim_hash_inputs.len(), 1);
    assert_eq!(inputs.exact_state_killshot_inputs.len(), 1);
    assert_eq!(proof.exact_state.len(), 1);
    assert_eq!(
        inputs.authorization_inputs.len(),
        inputs.authorization_witnesses.len()
    );
    assert_eq!(
        inputs.tx_body_standard_inputs.len(),
        inputs.tx_body_standard_hashes.len()
    );
    assert!(
        inputs.tx_body_sweep_inputs.is_empty() && proof.tx_body_sweep.is_none(),
        "sweep tier class not assembled yet"
    );
    // verify_authorization_components count check (structural side).
    assert_eq!(
        inputs.authorization_inputs.len(),
        inputs.authorization_totals.user_tx_count
    );

    // ---- Primary statement wires: header, claim, accumulator boundary.
    let header_inputs = header_hash_proof_inputs(&witness.headers);
    let header = HeaderHashInputsTrace::alloc(b, &header_inputs[0]);
    let start_acc = AccumulatorWires::alloc(b, start_accumulator);
    let end_acc = AccumulatorWires::alloc(b, end_accumulator);

    // ---- accepted_claim_hash component (fresh channel, killshot + [D]).
    let mut ch = RawChannelTrace::new();
    let (claim_inputs_t, _claim_reds) = build_accepted_claim_hash_slot(
        b,
        &mut ch,
        &proof.accepted_claim_hash,
        &inputs.accepted_claim_hash_inputs,
    );
    let claim = claim_inputs_t
        .into_iter()
        .next()
        .expect("single claim input");
    // Native: `input.expected_claim == accepted_block_claims[0]`.
    assert_eq!(
        inputs.accepted_claim_hash_inputs[0].expected_claim,
        witness.accepted_block_claims[0]
    );

    // The claim transcript's child-header section IS this header.
    use header_claim as hc;
    use header_fields as hf;
    pin_pair_at(b, &claim.fields, hc::BLOCK_ID, &header.expected_block_id);
    for (claim_at, field_at, lanes) in [
        (hc::PREV_BLOCK_HASH, hf::PREV_BLOCK_HASH, 2usize),
        (hc::STATE_ROOT, hf::STATE_ROOT, 2),
        (hc::TX_ROOT, hf::TX_ROOT, 2),
        (hc::TIMESTAMP, hf::TIMESTAMP, 1),
        (hc::HEIGHT, hf::HEIGHT, 1),
        (hc::MINER, hf::MINER, 2),
        (hc::NONCE, hf::NONCE, 1),
        (hc::TARGET, hf::TARGET, 2),
        (hc::LOG_SLOTS, hf::LOG_SLOTS, 1),
        (hc::ACTIVE_SLOT_COUNT, hf::ACTIVE_SLOT_COUNT, 1),
        (hc::ALLOC_COUNTER, hf::ALLOC_COUNTER, 1),
    ] {
        for lane in 0..lanes {
            pin_eq(b, &claim.fields[claim_at + lane], &header.fields[field_at + lane]);
        }
    }
    // Parent-section anchors: the parent's block id is the header's
    // prev_block_hash; the parent's state root and height are the start
    // accumulator's (`validate_accumulator_boundary` + the batch start
    // checks bind these natively).
    let parent = claim_layout::PARENT_SECTION;
    for lane in 0..2 {
        pin_eq(
            b,
            &claim.fields[parent + hc::BLOCK_ID + lane],
            &header.fields[hf::PREV_BLOCK_HASH + lane],
        );
        pin_eq(
            b,
            &claim.fields[parent + hc::STATE_ROOT + lane],
            &start_acc.state_root[lane],
        );
    }
    pin_eq(b, &claim.fields[parent + hc::HEIGHT], &start_acc.height);
    // First block height = start height + 1 (INTEGER successor). Field
    // addition is XOR, so a naive `child + parent + 1 = 0` would only be
    // the integer increment when the parent height is even; this is a
    // proper ripple-carry increment over the tower-bit decompositions.
    pin_u64_successor(b, &start_acc.height, &header.fields[hf::HEIGHT]);

    // ---- tx_body standard spine component.
    let (spine_inputs, tx_hashes) = if inputs.tx_body_standard_inputs.is_empty() {
        assert!(proof.tx_body_standard.is_none());
        (Vec::new(), Vec::new())
    } else {
        build_standard_tx_body_slot(
            b,
            proof
                .tx_body_standard
                .as_ref()
                .expect("standard spine proof present"),
            &inputs.tx_body_standard_inputs,
            &inputs.tx_body_standard_hashes,
        )
    };

    // ---- tx_root component: paths for the REAL leaves, position-pinned.
    let tx_root_paths = if inputs.tx_root_inputs.is_empty() {
        assert!(proof.tx_root.is_none());
        Vec::new()
    } else {
        let circuit = MerkleCircuit::build();
        let paths = build_batched_merkle_slot(
            b,
            &circuit,
            proof.tx_root.as_ref().expect("tx_root proof present"),
            &inputs.tx_root_inputs,
        );
        let n_txs = paths.len();
        assert_eq!(
            n_txs,
            tx_hashes.len(),
            "pure-standard tier: every tx is a spine instance"
        );
        let depth = paths[0].active_depth;
        assert_eq!(1usize << depth, n_txs.next_power_of_two().max(2));
        let rim = zero_subtree_lanes(depth);
        for (j, path) in paths.iter().enumerate() {
            assert_eq!(path.active_depth, depth);
            // Root = header tx_root; leaf = this tx's body hash.
            pin_pair_at(b, &header.fields.clone(), hf::TX_ROOT, &path.expected_root);
            pin_eq2(b, &path.leaf, &tx_hashes[j]);
            // Position binding: direction bits are the CONSTANT leaf-index
            // bits (block content never moves a tx to another slot).
            for (level, dir) in path.direction_bits.iter().enumerate() {
                let bit = (j >> level) & 1;
                pin_eq(b, dir, &const_block(Block128::from(bit as u128)));
            }
            // Padding rim: on the last real path every right-hand sibling
            // covers only padding leaves — pin it to the zero-subtree
            // constant of its level (the native root reconstruction binds
            // exactly this).
            if j == n_txs - 1 {
                for level in 0..depth {
                    if (j >> level) & 1 == 0 {
                        let z = rim[level];
                        pin_eq(b, &path.siblings[level][0], &const_block(z[0]));
                        pin_eq(b, &path.siblings[level][1], &const_block(z[1]));
                    }
                }
            }
        }
        paths
    };

    // ---- authorization components (per user tx): owner-auth killshot +
    // wallet-PCS discharge, tx_body_hash pinned to the spine hash.
    let mut auth_inputs = Vec::with_capacity(inputs.authorization_inputs.len());
    let mut pending_wallet_pcs: Vec<RegionPcsClaim> = Vec::new();
    // Region path: collect every tx's obligation; the whole block's wallet-PCS
    // discharges in ONE tiled plural call after the loop (all txs' capsule
    // families tile into one walk A/B/C, opening claims flat in tx count) so the
    // link IO tail stays class-fixed regardless of tx count. The inline path
    // (compact-FRI replay) stays per-tx.
    let mut region_obligations = Vec::new();
    let mut region_natives = Vec::new();
    let mut owner_sum = LinExpr::zero();
    let mut live_sum = LinExpr::zero();
    for (input, witness_proof) in inputs
        .authorization_inputs
        .iter()
        .zip(inputs.authorization_witnesses.iter())
    {
        assert_eq!(input.block_index, 0, "one block per link");
        // Native `verify_authorization_statement_proof` statement check.
        assert_eq!(input.tx_body_hash, input.public.tx_body_hash);
        let (inputs_t, obligation) = build_owner_auth_slot(b, witness_proof, &input.public);
        if config.discharge_wallet_pcs {
            match config.wallet_pcs_region {
                // Inline compact-FRI replay (proof-dependent shape).
                None => discharge_auth_pcs_obligation(b, &obligation, &witness_proof.pcs),
                // Shape-fixed region discharge: defer to ONE tiled call below.
                Some(_) => {
                    region_obligations.push(obligation);
                    region_natives.push(witness_proof.pcs.clone());
                }
            }
        }
        pin_eq2(b, &inputs_t.tx_body_hash, &tx_hashes[input.tx_index]);
        owner_sum = owner_sum.add(&inputs_t.owner_count);
        live_sum = live_sum.add(&inputs_t.live_len);
        auth_inputs.push(inputs_t);
    }
    // ONE tiled plural discharge for the whole block (region path): the K txs'
    // wallet-capsule families tile into one walk A/B/C and the returned committed-
    // column opening claims are flat in tx count, threading through the link's
    // public IO. `k` = tx count must be a power of two (the plural asserts it; a
    // tier pads its real txs to next_pow2 with ghost obligations).
    if let Some(params) = config.wallet_pcs_region {
        if !region_obligations.is_empty() {
            pending_wallet_pcs = discharge_auth_pcs_obligations_via_region(
                b,
                &region_obligations,
                &region_natives,
                params,
            );
        }
    }
    // Totals: per-slot sums AND the claim's resource lanes agree
    // (`verify_authorization_components` + the transcript encoding).
    let totals = &inputs.authorization_totals;
    let user_tx_count = const_block(Block128::from(totals.user_tx_count as u128));
    pin_eq(b, &claim.fields[claim_layout::USER_TX_COUNT], &user_tx_count);
    pin_eq(b, &claim.fields[claim_layout::LIVE_INPUT_COUNT], &live_sum);
    let owner_total = alloc_block(b, Block128::from(totals.owner_count_total as u128));
    pin_eq(b, &owner_total, &owner_sum);
    let tx_count = const_block(Block128::from(tx_hashes.len() as u128));
    pin_eq(b, &claim.fields[claim_layout::TX_COUNT], &tx_count);

    // ---- accepted-claim batch fold (claim part): shared statement wires,
    // no re-allocation — extend(state_root, block_id, height, claim).
    let steps = vec![ClaimBatchStepWires {
        block_id: header.expected_block_id.clone(),
        chain_claim: claim.expected_claim.clone(),
        state_root: [
            header.fields[hf::STATE_ROOT].clone(),
            header.fields[hf::STATE_ROOT + 1].clone(),
        ],
        height: header.fields[hf::HEIGHT].clone(),
    }];
    build_accepted_claim_batch_claim_slot(b, &start_acc, &steps, &end_acc);

    // ---- checkpoint_poseidon component over the SAME wires.
    let chain_inputs_t = ChainAccumulatorBatchInputsTrace {
        start_chain_hash: start_acc.chain_hash.clone(),
        items: vec![ChainAccumulatorItemTrace {
            block_id: header.expected_block_id.clone(),
            chain_claim: claim.expected_claim.clone(),
        }],
        expected_chain_hash: end_acc.chain_hash.clone(),
    };
    let header_slice = [header];
    build_checkpoint_poseidon_slot_with_inputs(
        b,
        &proof.checkpoint_poseidon,
        &header_slice,
        &chain_inputs_t,
        1,
    );
    let [header] = header_slice;

    // ---- exact_state component + its statement anchors.
    let exact_state = build_exact_state_slot(
        b,
        &inputs.exact_state_killshot_inputs[0],
        &proof.exact_state[0],
    );
    assert_eq!(exact_state.state_roots.len(), 2, "parent/child pair");
    for lane in 0..2 {
        pin_eq(
            b,
            &exact_state.state_roots[0].expected_state_root[lane],
            &claim.fields[parent + hc::STATE_ROOT + lane],
        );
        pin_eq(
            b,
            &exact_state.state_roots[1].expected_state_root[lane],
            &header.fields[hf::STATE_ROOT + lane],
        );
    }
    pin_eq(
        b,
        &exact_state.state_roots[0].log_slots,
        &claim.fields[parent + hc::LOG_SLOTS],
    );
    pin_eq(
        b,
        &exact_state.state_roots[1].log_slots,
        &header.fields[hf::LOG_SLOTS],
    );

    BlockSlots {
        header,
        claim,
        start_acc,
        end_acc,
        spine_inputs,
        tx_hashes,
        tx_root_paths,
        auth_inputs,
        exact_state,
        pending_wallet_pcs,
    }
}

/// The region wallet-PCS opening claims' native `(point, value)` per claim, via
/// a lightweight scratch discharge over ONLY the per-tx owner-auth slots + the
/// region discharge — SKIPPING the block-[B] killshots (~2.7M wires @1 tx),
/// which do not affect the region native values.
///
/// The link fills its public-IO envelope from these BEFORE the real trace
/// allocates the fixed-position IO cells; the claim WIRES + committed-column
/// SLICES come from the real (full) build. The region discharge is driven
/// solely by each tx's owner-auth obligation (`commitment_cap_lanes` +
/// `reduction`), so the native `(point, value)` here are identical to the
/// full-block build — only the committed-column slices differ (supplied by the
/// real build, not here). This is what lets the link recover the IO values
/// without building the whole block slots twice (the block-[B] half is no
/// longer duplicated; only the region discharge is, and that is unavoidable
/// while the IO cells sit at a fixed early position).
pub fn region_wallet_pcs_native(
    inputs: &AcceptedBlockBatchComponentInputs,
    params: RegionDischargeParams,
) -> Vec<(Vec<F128>, F128)> {
    let mut pb = FieldR1csBuilder::new();
    let mut obligations = Vec::new();
    let mut natives = Vec::new();
    for (input, witness_proof) in inputs
        .authorization_inputs
        .iter()
        .zip(inputs.authorization_witnesses.iter())
    {
        let (_inputs_t, obligation) = build_owner_auth_slot(&mut pb, witness_proof, &input.public);
        obligations.push(obligation);
        natives.push(witness_proof.pcs.clone());
    }
    if obligations.is_empty() {
        return Vec::new();
    }
    // ONE tiled plural discharge -- the same call the real block-slots build makes.
    // The region `(point, value)` depend only on each tx's obligation + native
    // proof (not on the wire positions or the [B] killshots), so they are
    // identical to the full build; only the committed-column SLICES differ (the
    // link takes those from the real build).
    discharge_auth_pcs_obligations_via_region(&mut pb, &obligations, &natives, params)
        .into_iter()
        .map(|c| (c.native_point, c.native_value))
        .collect()
}
