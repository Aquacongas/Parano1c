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
//!   roots) — IN INLINE MODE ONLY (`exact_state_region = false`): each of
//!   the five killshots self-binds its own hash chain, but the
//!   cross-killshot gluing (state-path root == composite utxo_root, and
//!   likewise for guard) is a free witness pair, natively guaranteed by
//!   `derive_exact_state_killshot_inputs` re-deriving every input from the
//!   one validated block. REGION MODE (`exact_state_region = true`) CLOSES
//!   this residue: the slot-leaf sponge tiles pin their digest cells to the
//!   `expected_leaf` statement wires, the walk-B state-leg entry cells pin
//!   to the SAME wires (leaf ↔ path), and each leg root cell pins to the
//!   composite-root statement's utxo/guard-root wires (path ↔ root).
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
use super::trace::region_source_binding::{
    discharge_auth_pcs_obligations_via_region, discharge_owner_auth_killshots_via_region,
    RegionDischargeParams, RegionPcsClaim, SpineInstanceRegion, SpineRegionData,
    TxRootPathRegion, TxRootRegionData,
};
use noid_gkr::SpineInputs;
use noid_ivc_core::deep_chain::spine::SpineInstanceFlat;
use super::trace::checkpoint_poseidon::{
    build_checkpoint_poseidon_slot_with_inputs, ChainAccumulatorBatchInputsTrace,
    ChainAccumulatorItemTrace, HeaderHashInputsTrace,
};
use super::trace::exact_state::{
    build_exact_state_slot_with_config, scratch_exact_state_region_data, ExactStateSlotWires,
};
use super::trace::merkle_path::{build_batched_merkle_slot, MerklePathInputsTrace};
use super::trace::owner_auth::{
    build_owner_auth_slot, OwnerAuthProofTrace, OwnerAuthPublicInputsTrace,
};
use super::trace::tx_body_spine::{build_standard_tx_body_slot, SpineInputsTrace};
use super::trace::{
    alloc_block, const_block, flat_const, flat_of, mul, pin_eq, pin_zero, range_check_bits,
    FieldR1csBuilder, LinExpr, RawChannelTrace, F128,
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

/// `a + c` as an INTEGER (ripple-carry full adder over `n` tower bits). Both
/// operands are range-checked `< 2^n` and the final carry is pinned to zero (no
/// overflow), so the reconstruction is exactly the integer sum. Field addition
/// alone is XOR in GF(2^128), which is NOT integer addition once a carry occurs.
fn u64_add(b: &mut FieldR1csBuilder, a: &LinExpr, c: &LinExpr, n: usize) -> LinExpr {
    let a_bits = range_check_bits(b, a, n);
    let c_bits = range_check_bits(b, c, n);
    let mut carry = LinExpr::zero();
    let mut terms: Vec<LinExpr> = Vec::with_capacity(n);
    for i in 0..n {
        let ai = LinExpr::from_wire(a_bits[i]);
        let ci = LinExpr::from_wire(c_bits[i]);
        // sum_i = a_i XOR c_i XOR carry_i.
        let sum_i = ai.add(&ci).add(&carry);
        terms.push(sum_i.scale(flat_const(1u128 << i)));
        // carry_{i+1} = a_i·c_i + carry_i·(a_i XOR c_i)  (the full-adder majority;
        // the two products are never both 1, so the char-2 add IS the OR).
        let ai_ci = mul(b, &ai, &ci);
        let axc = ai.add(&ci);
        let carry_axc = mul(b, &carry, &axc);
        carry = ai_ci.add(&carry_axc);
    }
    pin_zero(b, &carry);
    let mut recon = LinExpr::zero();
    for t in &terms {
        recon = recon.add(t);
    }
    recon
}

/// `Σ terms` as an INTEGER. A single term is returned unchanged (no adder wires),
/// so a single-tx block reproduces the former single-count path exactly; K terms
/// cost K−1 ripple-carry adds. 16 bits hold any block total (≤ 255·255 < 2^16).
fn pin_u64_sum(b: &mut FieldR1csBuilder, terms: &[LinExpr]) -> LinExpr {
    const N: usize = 16;
    match terms.split_first() {
        None => LinExpr::zero(),
        Some((first, rest)) => {
            let mut acc = first.clone();
            for t in rest {
                acc = u64_add(b, &acc, t, N);
            }
            acc
        }
    }
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

/// Assemble the tx-root region handoff from already-allocated statement
/// wires — the real build passes the header `tx_root` pair + the spine
/// tx-hash wires; the scratch mirror passes throwaway allocs of the same
/// natives. Pure transliteration of the killshot statement (depth, one path
/// per tx in tx order, shared expected root, rim constants); every wire is
/// asserted to carry its native value at build time.
fn tx_root_region_data_from_wires(
    b: &FieldR1csBuilder,
    tx_root_inputs: &[noid_gkr::merkle_circuit::MerklePathInputs],
    root_w: [LinExpr; 2],
    entry_ws: &[[LinExpr; 2]],
) -> TxRootRegionData {
    let n_txs = tx_root_inputs.len();
    assert!(n_txs > 0, "tx-root region handoff without paths");
    assert_eq!(
        n_txs,
        entry_ws.len(),
        "pure-standard tier: every tx is a spine instance"
    );
    let depth = tx_root_inputs[0].active_depth;
    assert_eq!(1usize << depth, n_txs.next_power_of_two().max(2));
    let root_native = tx_root_inputs[0].expected_root;
    let root_flat = [flat_of(root_native[0]), flat_of(root_native[1])];
    for lane in 0..2 {
        assert_eq!(
            root_w[lane].eval(b.values()),
            root_flat[lane],
            "header tx_root wire != the killshot statement root"
        );
    }
    let paths: Vec<TxRootPathRegion> = tx_root_inputs
        .iter()
        .enumerate()
        .map(|(j, p)| {
            assert_eq!(p.active_depth, depth, "all tx-root paths share the depth");
            assert_eq!(
                p.expected_root, root_native,
                "tx-root path {j} root != the header tx_root"
            );
            let entry_flat = [flat_of(p.leaf[0]), flat_of(p.leaf[1])];
            for lane in 0..2 {
                assert_eq!(
                    entry_ws[j][lane].eval(b.values()),
                    entry_flat[lane],
                    "spine tx hash {j} != the tx-root leaf"
                );
            }
            TxRootPathRegion {
                entry_w: entry_ws[j].clone(),
                entry_flat,
                siblings: p.siblings[..depth]
                    .iter()
                    .map(|s| [flat_of(s[0]), flat_of(s[1])])
                    .collect(),
            }
        })
        .collect();
    TxRootRegionData {
        depth,
        root_w,
        root_flat,
        paths,
        rim_flat: zero_subtree_lanes(depth)
            .iter()
            .map(|z| [flat_of(z[0]), flat_of(z[1])])
            .collect(),
    }
}

/// The real build's tx-root handoff: header `tx_root` wires + spine tx-hash
/// wires (the shared-wire leaf/root closures).
fn tx_root_region_handoff(
    b: &FieldR1csBuilder,
    tx_root_inputs: &[noid_gkr::merkle_circuit::MerklePathInputs],
    header: &HeaderHashInputsTrace,
    tx_hashes: &[[LinExpr; 2]],
) -> TxRootRegionData {
    let root_w = [
        header.fields[header_fields::TX_ROOT].clone(),
        header.fields[header_fields::TX_ROOT + 1].clone(),
    ];
    tx_root_region_data_from_wires(b, tx_root_inputs, root_w, tx_hashes)
}

/// Tx-root region handoff on THROWAWAY wires (fresh allocs of the same
/// natives) — the `region_wallet_pcs_native` mirror; the plural's native
/// claim `(point, value)` sequences depend only on native values + layout.
fn scratch_tx_root_region_data(
    pb: &mut FieldR1csBuilder,
    tx_root_inputs: &[noid_gkr::merkle_circuit::MerklePathInputs],
) -> TxRootRegionData {
    let root_native = tx_root_inputs[0].expected_root;
    let root_w = [
        alloc_block(pb, root_native[0]),
        alloc_block(pb, root_native[1]),
    ];
    let entry_ws: Vec<[LinExpr; 2]> = tx_root_inputs
        .iter()
        .map(|p| [alloc_block(pb, p.leaf[0]), alloc_block(pb, p.leaf[1])])
        .collect();
    tx_root_region_data_from_wires(pb, tx_root_inputs, root_w, &entry_ws)
}

/// The padded tx-tree levels rebuilt from the real tx-body hashes: leaves =
/// the hash digests padded to `2^depth` with the zero digest, then the
/// `compress` ladder — exactly the native `tx_root_merkle_inputs`
/// construction, giving the sibling sets of EVERY leaf (real and padding).
fn padded_tx_tree_levels(hashes: &[[Block128; 2]], depth: usize) -> Vec<Vec<[u8; 32]>> {
    let target = 1usize << depth;
    assert!(hashes.len() <= target, "more txs than tree leaves");
    let mut level: Vec<[u8; 32]> = hashes
        .iter()
        .map(|h| {
            let mut d = [0u8; 32];
            d[..16].copy_from_slice(&h[0].0.to_le_bytes());
            d[16..].copy_from_slice(&h[1].0.to_le_bytes());
            d
        })
        .collect();
    level.resize(target, [0u8; 32]);
    let mut levels = vec![level.clone()];
    while level.len() > 1 {
        level = level.chunks_exact(2).map(|p| compress(&p[0], &p[1])).collect();
        levels.push(level.clone());
    }
    levels
}

/// The tier-capacity tx-root handoff: one walk-B path per PADDED-TREE leaf.
/// Leaf `j`'s entry is the live-muxed `live_j · tx_hash_j` (a dead leaf
/// proves the ZERO padding digest), where `live_j` is `1` for the coinbase
/// leaf (when the block carries one), the authorization liveness bit for a
/// user leaf, and `0` for leaves past the capacity. The rim const pins are
/// subsumed: every padding leaf is authenticated as zero directly.
fn tx_root_region_capacity_handoff(
    b: &mut FieldR1csBuilder,
    tx_root_inputs: &[noid_gkr::merkle_circuit::MerklePathInputs],
    real_hashes: &[[Block128; 2]],
    header: &HeaderHashInputsTrace,
    tx_hashes: &[[LinExpr; 2]],
    live_bits: &[LinExpr],
    tx_delta: usize,
) -> TxRootRegionData {
    let root_w = [
        header.fields[header_fields::TX_ROOT].clone(),
        header.fields[header_fields::TX_ROOT + 1].clone(),
    ];
    tx_root_region_capacity_data_from_wires(
        b,
        tx_root_inputs,
        real_hashes,
        root_w,
        tx_hashes,
        live_bits,
        tx_delta,
    )
}

/// [`tx_root_region_capacity_handoff`] core on caller-supplied wires (the
/// real build passes the header root + statement liveness; the scratch
/// mirror passes throwaway allocs of the same natives).
fn tx_root_region_capacity_data_from_wires(
    b: &mut FieldR1csBuilder,
    tx_root_inputs: &[noid_gkr::merkle_circuit::MerklePathInputs],
    real_hashes: &[[Block128; 2]],
    root_w: [LinExpr; 2],
    tx_hashes: &[[LinExpr; 2]],
    live_bits: &[LinExpr],
    tx_delta: usize,
) -> TxRootRegionData {
    assert!(!tx_root_inputs.is_empty(), "tx-root region handoff without paths");
    let depth = tx_root_inputs[0].active_depth;
    let n_leaves = 1usize << depth;
    let n_real = real_hashes.len();
    assert!(n_real >= 1 && n_real <= n_leaves);
    assert_eq!(
        n_leaves,
        tx_hashes.len().next_power_of_two().max(2),
        "tier tx capacity must fill the padded tx-tree depth"
    );
    let root_native = tx_root_inputs[0].expected_root;
    let root_flat = [flat_of(root_native[0]), flat_of(root_native[1])];
    for lane in 0..2 {
        assert_eq!(
            root_w[lane].eval(b.values()),
            root_flat[lane],
            "header tx_root wire != the killshot statement root"
        );
    }
    let levels = padded_tx_tree_levels(real_hashes, depth);
    // Cross-check the rebuilt root against the killshot statement.
    assert_eq!(digest_lanes(&levels[depth][0]), root_native, "rebuilt padded tree root");

    let paths: Vec<TxRootPathRegion> = (0..n_leaves)
        .map(|j| {
            // Leaf liveness: coinbase (when present) is leaf 0 and always
            // live; user leaf u = j - tx_delta takes its authorization
            // liveness bit; leaves past the capacity are dead constants.
            let live: LinExpr = if tx_delta == 1 && j == 0 {
                LinExpr::constant(F128::ONE)
            } else {
                let u = j - tx_delta;
                if u < live_bits.len() {
                    live_bits[u].clone()
                } else {
                    LinExpr::zero()
                }
            };
            let entry_w: [LinExpr; 2] = if j < tx_hashes.len() {
                std::array::from_fn(|lane| mul(b, &live, &tx_hashes[j][lane]))
            } else {
                [LinExpr::zero(), LinExpr::zero()]
            };
            let entry_native = digest_lanes(&levels[0][j]);
            let entry_flat = [flat_of(entry_native[0]), flat_of(entry_native[1])];
            for lane in 0..2 {
                assert_eq!(
                    entry_w[lane].eval(b.values()),
                    entry_flat[lane],
                    "live-muxed tx-root entry {j} != the padded-tree leaf"
                );
            }
            let siblings: Vec<[F128; 2]> = (0..depth)
                .map(|l| {
                    let sib = levels[l][(j >> l) ^ 1];
                    let lanes = digest_lanes(&sib);
                    [flat_of(lanes[0]), flat_of(lanes[1])]
                })
                .collect();
            TxRootPathRegion { entry_w, entry_flat, siblings }
        })
        .collect();
    TxRootRegionData {
        depth,
        root_w,
        root_flat,
        paths,
        // No rim constants: every padding leaf is authenticated directly.
        rim_flat: Vec::new(),
    }
}

/// Authorization-slot count of a build: at tier capacity, the capacity
/// rounded up to the next power of two — the walk tiling requires a
/// power-of-two per-slot obligation count, and 255 is the one non-power
/// tier. Slots past the consensus capacity are PAD slots: they prove the
/// same protocol ghost authorization as the in-capacity ghost slots, but no
/// tx slot exists behind them, so their body-hash pin lands on the
/// ghost-body constant and their liveness bit stays zero-valued (the
/// USER_TX_COUNT sum is unchanged). Non-capacity builds keep the caller's
/// tx count (the plural discharge asserts it is a power of two).
fn tier_auth_slot_count(tier_user_tx_capacity: Option<usize>, n_real_user: usize) -> usize {
    tier_user_tx_capacity
        .map_or(n_real_user, |c| if c == 0 { 0 } else { c.next_power_of_two() })
}

/// The tier's touched-slot capacity: the class spend capacity (the guard
/// bucket's padded spend width) plus the output capacity (every standard tx
/// may create up to its shape's max outputs). Every touched slot is a spend
/// or a creation, so the real touched count never exceeds this.
fn tier_touched_capacity(std_tier: usize) -> usize {
    let spend = noid_chain::consensus::params::block_class_spend_capacity(std_tier, 0);
    spend + std_tier * noid_gkr::tx_body_layout::TXBODY_N_OUTPUT_LEAVES
}

/// Pad the exact-state statement to the tier's touched capacity: the
/// `slot_leaves`/`state_paths` old and new HALVES each grow to
/// [`tier_touched_capacity`] entries by duplicating the half's first
/// leaf+path pair (re-proving a real leaf against the same root —
/// value-neutral). Guard and composite-root parts are already
/// per-block-fixed.
fn pad_exact_state_inputs_to_tier(
    es: &crate::block_certificate_backend::ExactStateKillShotInputs,
    std_tier: usize,
) -> crate::block_certificate_backend::ExactStateKillShotInputs {
    let cap = tier_touched_capacity(std_tier);
    let t = es.slot_leaves.len() / 2;
    assert_eq!(es.slot_leaves.len(), 2 * t, "old/new leaf halves");
    assert_eq!(es.state_paths.len(), 2 * t, "old/new path halves");
    assert!(t >= 1 && t <= cap, "touched count {t} exceeds tier capacity {cap}");
    let mut out = es.clone();
    fn dup_half<T: Clone>(v: &mut Vec<T>, half_start: usize, t: usize, cap: usize) {
        let template = v[half_start].clone();
        let insert_at = half_start + t;
        for _ in t..cap {
            v.insert(insert_at, template.clone());
        }
    }
    // New half first so the old half's indices stay valid while inserting.
    dup_half(&mut out.slot_leaves, t, t, cap);
    dup_half(&mut out.state_paths, t, t, cap);
    dup_half(&mut out.slot_leaves, 0, t, cap);
    dup_half(&mut out.state_paths, 0, t, cap);
    assert_eq!(out.slot_leaves.len(), 2 * cap);
    assert_eq!(out.state_paths.len(), 2 * cap);
    out
}

/// The flat image of one native `SpineInputs` statement (φ lane by lane).
fn spine_instance_flat(n: &SpineInputs) -> SpineInstanceFlat {
    SpineInstanceFlat {
        epoch_anchor: std::array::from_fn(|i| flat_of(n.epoch_anchor[i])),
        fee_leaf: std::array::from_fn(|i| flat_of(n.fee_leaf[i])),
        input_leaves: std::array::from_fn(|c| {
            std::array::from_fn(|i| flat_of(n.input_leaves[c][i]))
        }),
        output_leaves: std::array::from_fn(|o| {
            std::array::from_fn(|i| flat_of(n.output_leaves[o][i]))
        }),
        is_coinbase_leaf: std::array::from_fn(|i| flat_of(n.is_coinbase_leaf[i])),
        pad_leaf: std::array::from_fn(|i| flat_of(n.pad_leaf[i])),
    }
}

/// Assemble the tx-body spine region handoff from already-allocated
/// statement wires — the real build passes the spine statement wires + the
/// tx-hash wires; the scratch mirror passes throwaway allocs of the same
/// natives. Every wire is asserted to carry its native flat value at build
/// time (a pure transliteration; the region cell pins do the binding).
fn spine_region_data_from_wires(
    b: &FieldR1csBuilder,
    natives: &[SpineInputs],
    native_hashes: &[[Block128; 2]],
    inputs_t: &[SpineInputsTrace],
    tx_hashes: &[[LinExpr; 2]],
) -> SpineRegionData {
    assert_eq!(natives.len(), inputs_t.len(), "one wire set per spine instance");
    assert_eq!(natives.len(), native_hashes.len(), "one hash per spine instance");
    assert_eq!(natives.len(), tx_hashes.len(), "one hash wire pair per instance");
    let assert_pair = |w: &[LinExpr; 2], n: &[Block128; 2], what: &str| {
        for lane in 0..2 {
            assert_eq!(w[lane].eval(b.values()), flat_of(n[lane]), "{what} lane {lane}");
        }
    };
    let instances = natives
        .iter()
        .zip(native_hashes.iter())
        .zip(inputs_t.iter().zip(tx_hashes.iter()))
        .map(|((n, h), (t, hw))| {
            assert_eq!(t.input_leaves.len(), n.input_leaves.len());
            assert_eq!(t.output_leaves.len(), n.output_leaves.len());
            for (c, w4) in t.input_leaves.iter().enumerate() {
                for i in 0..4 {
                    assert_eq!(
                        w4[i].eval(b.values()),
                        flat_of(n.input_leaves[c][i]),
                        "spine input leaf wire"
                    );
                }
            }
            for (o, w4) in t.output_leaves.iter().enumerate() {
                for i in 0..4 {
                    assert_eq!(
                        w4[i].eval(b.values()),
                        flat_of(n.output_leaves[o][i]),
                        "spine output leaf wire"
                    );
                }
            }
            assert_pair(&t.epoch_anchor, &n.epoch_anchor, "spine anchor");
            assert_pair(&t.fee_leaf, &n.fee_leaf, "spine fee");
            assert_pair(&t.is_coinbase_leaf, &n.is_coinbase_leaf, "spine coinbase");
            assert_pair(&t.pad_leaf, &n.pad_leaf, "spine pad");
            assert_pair(hw, h, "spine tx hash");
            SpineInstanceRegion {
                flat: spine_instance_flat(n),
                input_leaves_w: t.input_leaves.clone(),
                output_leaves_w: t.output_leaves.clone(),
                anchor_w: t.epoch_anchor.clone(),
                fee_w: t.fee_leaf.clone(),
                coinbase_w: t.is_coinbase_leaf.clone(),
                pad_w: t.pad_leaf.clone(),
                tx_hash_w: hw.clone(),
                tx_hash_flat: [flat_of(h[0]), flat_of(h[1])],
            }
        })
        .collect();
    SpineRegionData { instances }
}

/// Spine region handoff on THROWAWAY wires — the `region_wallet_pcs_native`
/// mirror.
fn scratch_spine_region_data(
    pb: &mut FieldR1csBuilder,
    natives: &[SpineInputs],
    native_hashes: &[[Block128; 2]],
) -> SpineRegionData {
    let inputs_t: Vec<SpineInputsTrace> =
        natives.iter().map(|i| SpineInputsTrace::alloc(pb, i)).collect();
    let tx_hashes: Vec<[LinExpr; 2]> = native_hashes
        .iter()
        .map(|h| std::array::from_fn(|i| alloc_block(pb, h[i])))
        .collect();
    spine_region_data_from_wires(pb, natives, native_hashes, &inputs_t, &tx_hashes)
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
    /// Per-authorization-slot liveness bits (all ONE without tier capacity;
    /// real slots ONE / ghost slots ZERO at capacity). Boolean + monotone;
    /// their integer sum pins to the claim's USER_TX_COUNT lane at capacity.
    pub live_bits: Vec<LinExpr>,
    pub exact_state: ExactStateSlotWires,
    /// Committed-column opening claims emitted by the region wallet-PCS
    /// discharge (empty unless `BlockSlotsConfig::discharge_wallet_pcs` was set).
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
    /// Parameters of the SHAPE-FIXED region wallet-PCS discharge
    /// (`discharge_auth_pcs_obligation_via_region`) — the ONLY wallet-PCS
    /// mode (the inline compact-FRI replay was deleted with the capsule
    /// regeometry). The region discharge is class-fixed (its trace structure
    /// does NOT drift with the proof), and it emits committed-column opening
    /// claims collected into [`BlockSlots::pending_wallet_pcs`] for the link
    /// to thread through public-IO. Only consulted when
    /// `discharge_wallet_pcs` is true.
    pub wallet_pcs_params: RegionDischargeParams,
    /// When true, verify the block's owner-authorization killshots via the
    /// SHAPE-FIXED region KSCHANNL walk-C discharge
    /// (`discharge_owner_auth_killshots_via_region`) instead of the inline
    /// per-tx channel replay (`build_owner_auth_slot`). This replays all K
    /// KSCHANNL transcripts on ONE tiled data-parallel walk, so owner-auth
    /// verification (the dominant per-tx [K] piece) is transaction-count flat.
    ///
    /// REQUIRES `discharge_wallet_pcs`: the region owner-auth discharge
    /// PRODUCES the [`super::trace::owner_auth::PendingAuthPcsObligation`]s that
    /// the wallet-PCS region discharge then CONSUMES, and its own walk-C
    /// committed-column opening claims (which bind the owner-auth transcript)
    /// are collected into [`BlockSlots::pending_wallet_pcs`] (BEFORE the
    /// wallet-PCS claims) for the link to thread through public-IO, so both must
    /// be discharged for a complete proof. `false` = the inline per-tx replay.
    pub owner_auth_region: bool,
    /// When true, verify the exact-state HASHING killshots (slot_leaves,
    /// state_paths, guard_paths — the per-touched-slot-growing pieces) via the
    /// shared region walks instead of the inline per-slot replays: the slot-leaf
    /// sponge tiles join the wallet-PCS discharge's walk A, the state/guard
    /// Merkle paths join its walk B as extra legs (`ExactStateRegionData`
    /// threaded into the plural discharge). guard_buckets and state_roots stay
    /// inline. Region mode ALSO closes the exact-state internal-wiring residue
    /// (leaf↔path↔root — see the module doc).
    ///
    /// REQUIRES `discharge_wallet_pcs`: the exact-state families ride
    /// the wallet-PCS region walks (a new walk is never spawned), so the plural
    /// discharge must run. `false` = the inline killshot replays.
    pub exact_state_region: bool,
    /// When true, verify the tx-root Merkle paths via the shared region walks
    /// instead of the inline batched killshot: one TAG_COMPRESS walk-B leg,
    /// entries = the SPINE tx-hash wires, roots = the header `tx_root` wires,
    /// leaf positions bound by const-pinning the committed direction cells to
    /// the leaf-index bits, and the padding rim by const-pinning the last real
    /// path's right-hand sibling cells to the zero-subtree constants — exactly
    /// the bindings the inline slot pins on its statement wires.
    ///
    /// REQUIRES `discharge_wallet_pcs` (the leg rides walk B).
    /// `false` = the inline killshot replay.
    pub tx_root_region: bool,
    /// When true, verify every transaction's 59-permutation tx-body spine via
    /// the shared region walks instead of the inline batched killshot: each
    /// instance's 12 leaf sub-sponges + wrap ride walk A as a 32-slot
    /// region-gated sponge tile and its 16-leaf compress tree as a 64-slot
    /// source-tree-shaped family (zero LEAFODD, gated internal-child
    /// exposure). The leaf payload statement wires pin to the tile absorb
    /// cells, the chain digests join the tree KID leaf cells as shared wires,
    /// the statement lanes (anchor/fee/coinbase/pad) pin the remaining KID
    /// leaves, and the wrap digest pins to the `tx_hashes` statement wires —
    /// the same wires the tx-root leg and the owner-auth statements consume,
    /// so downstream bindings are untouched.
    ///
    /// REQUIRES `discharge_wallet_pcs` (the families ride walk A).
    /// `false` = the inline killshot replay.
    pub spine_region: bool,
    /// When `Some(cap)`, assemble the block at its consensus-tier USER-TX
    /// CAPACITY so two same-tier blocks with DIFFERENT real usage share ONE
    /// class matrix: the authorization loop runs over `cap` slots (real txs
    /// first, then canonical GHOST slots proving the protocol
    /// `ghost_authorization()`), a per-slot LIVENESS bit vector (boolean,
    /// monotone, summing to the claim's `USER_TX_COUNT` lane) gates every
    /// count that reaches the claim lanes, the spine region carries
    /// capacity-many instances (real bodies ++ ghost bodies) so `tx_hashes`
    /// is capacity-length, and the tx-root leg authenticates EVERY leaf of
    /// the padded tx tree (entries live-muxed: a dead leaf proves the ZERO
    /// padding digest), replacing the content-shaped rim/count const pins
    /// with class-fixed structure.
    ///
    /// `cap` MUST be the block's consensus standard-tx class tier
    /// (`standard_tx_class_tier(n_real)`), so the native tier-quantized
    /// statements (exact-state spend capacity, guard capacity, padded
    /// tx-tree depth) already agree across the tier. REQUIRES the full
    /// region stack (all four region flags). `None` = exact counts (the
    /// per-block shapes; the pre-capacity behavior).
    pub tier_user_tx_capacity: Option<usize>,
}

impl Default for BlockSlotsConfig {
    fn default() -> Self {
        Self {
            discharge_wallet_pcs: true,
            wallet_pcs_params: RegionDischargeParams {
                nq: noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
            },
            owner_auth_region: false,
            exact_state_region: false,
            tx_root_region: false,
            spine_region: false,
            tier_user_tx_capacity: None,
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
    assert!(
        !config.exact_state_region || config.discharge_wallet_pcs,
        "exact_state_region requires the wallet-PCS discharge (the exact-state families \
         ride the wallet-PCS region walks; a new walk is never spawned)"
    );
    assert!(
        !config.tx_root_region || config.discharge_wallet_pcs,
        "tx_root_region requires the wallet-PCS discharge (the tx-root leg rides the \
         wallet-PCS region walk B; a new walk is never spawned)"
    );
    assert!(
        !config.spine_region || config.discharge_wallet_pcs,
        "spine_region requires the wallet-PCS discharge (the spine families ride the \
         wallet-PCS region walk A; a new walk is never spawned)"
    );
    if let Some(cap) = config.tier_user_tx_capacity {
        assert!(
            config.discharge_wallet_pcs
                && config.owner_auth_region
                && config.exact_state_region
                && config.tx_root_region
                && config.spine_region,
            "tier capacity requires the full region stack (all four region flags)"
        );
        assert_eq!(
            noid_chain::consensus::params::standard_tx_class_tier(
                inputs.authorization_inputs.len()
            ),
            Some(cap),
            "tier capacity must be the block's consensus standard-tx class tier"
        );
    }

    let mut ledger = b.num_wires();

    // ---- Primary statement wires: header, claim, accumulator boundary.
    let header_inputs = header_hash_proof_inputs(&witness.headers);
    let header = HeaderHashInputsTrace::alloc(b, &header_inputs[0]);
    let start_acc = AccumulatorWires::alloc(b, start_accumulator);
    let end_acc = AccumulatorWires::alloc(b, end_accumulator);

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: statement wires");
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

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: claim-hash killshot+[D]");
    // ---- tx_body standard spine component. Region mode moves the whole
    // 59-permutation-per-tx replay onto the shared walk A (leaf/wrap tile +
    // compress tree): only the statement wires are allocated here — the SAME
    // wire vectors the inline slot returns, so every downstream consumer
    // (tx-root leaves, owner-auth tx_body_hash pins, claim lanes) is
    // untouched — and the handoff carries them into the plural discharge.
    // The inline killshot proof is not consumed in-trace (nodes still verify
    // it natively; π proves the statement directly).
    let mut spine_region_data: Option<SpineRegionData> = None;
    // Tier capacity: the block carries capacity-many tx slots — the real
    // transactions followed by canonical GHOST-body slots (the protocol
    // ghost tx), so `tx_hashes`/`spine_inputs` are capacity-length and every
    // per-tx-slot structure below is class-fixed. `delta` = non-user txs
    // (the coinbase when present) — a class constant within a tier.
    let n_real_txs = inputs.tx_body_standard_inputs.len();
    let tx_delta = n_real_txs
        .checked_sub(inputs.authorization_inputs.len())
        .expect("every user tx is a spine instance");
    assert!(tx_delta <= 1, "at most one non-user (coinbase) tx per block");
    let cap_txs = config
        .tier_user_tx_capacity
        .map_or(n_real_txs, |c| c + tx_delta);
    let (spine_inputs, tx_hashes) = if inputs.tx_body_standard_inputs.is_empty() {
        assert!(proof.tx_body_standard.is_none());
        (Vec::new(), Vec::new())
    } else if config.spine_region {
        let mut spine_natives: Vec<SpineInputs> = inputs.tx_body_standard_inputs.clone();
        let mut hash_natives: Vec<[Block128; 2]> = inputs.tx_body_standard_hashes.clone();
        if cap_txs > n_real_txs {
            let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
            let ghost_spine = noid_gkr::spine_statement::spine_inputs_from_body(&ghost_body)
                .expect("the canonical ghost body has spine inputs");
            let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
            for _ in n_real_txs..cap_txs {
                spine_natives.push(ghost_spine.clone());
                hash_natives.push(ghost_hash);
            }
        }
        let inputs_t: Vec<SpineInputsTrace> =
            spine_natives.iter().map(|i| SpineInputsTrace::alloc(b, i)).collect();
        let hashes_t: Vec<[LinExpr; 2]> = hash_natives
            .iter()
            .map(|h| std::array::from_fn(|i| alloc_block(b, h[i])))
            .collect();
        spine_region_data = Some(spine_region_data_from_wires(
            b,
            &spine_natives,
            &hash_natives,
            &inputs_t,
            &hashes_t,
        ));
        (inputs_t, hashes_t)
    } else {
        assert!(
            config.tier_user_tx_capacity.is_none(),
            "tier capacity requires spine_region"
        );
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

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: spine (tiles+tree data)");
    // ---- Slot liveness (tier capacity): one witness bit per authorization
    // slot — 1 for the real txs, 0 for the ghost padding. Boolean and
    // MONOTONE (no live slot after a dead one), so the vector is determined
    // by its integer sum, which pins to the claim's USER_TX_COUNT lane
    // below. Every count that reaches a claim lane is gated by these bits,
    // replacing the content-shaped const pins with class-fixed structure.
    let n_real_user = inputs.authorization_inputs.len();
    let n_auth_slots = tier_auth_slot_count(config.tier_user_tx_capacity, n_real_user);
    let live_bits: Vec<LinExpr> = (0..n_auth_slots)
        .map(|i| {
            let v = Block128::from(if i < n_real_user { 1u128 } else { 0u128 });
            alloc_block(b, v)
        })
        .collect();
    if config.tier_user_tx_capacity.is_some() {
        for w in &live_bits {
            // Booleanity: w^2 = w.
            let sq = mul(b, w, w);
            pin_eq(b, &sq, w);
        }
        for i in 0..n_auth_slots.saturating_sub(1) {
            // Monotone: live[i+1] * (1 + live[i]) = 0 (char 2: 1+x = 1-x).
            let not_prev = live_bits[i].add_const(F128::ONE);
            let t = mul(b, &live_bits[i + 1], &not_prev);
            pin_zero(b, &t);
        }
    }

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: liveness bits");
    // ---- tx_root component: paths for the REAL leaves, position-pinned.
    // Region mode moves the path hashing onto the shared walk B (one
    // TAG_COMPRESS leg): the entry/root closures ride the SAME statement
    // wires (spine tx hashes / header tx_root) via cell pins, and the
    // position + padding-rim bindings become const cell pins on the
    // committed direction/sibling cells — the exact constants pinned below
    // on the inline slot's statement wires.
    let mut tx_root_region_data: Option<TxRootRegionData> = None;
    let tx_root_paths = if inputs.tx_root_inputs.is_empty() {
        assert!(proof.tx_root.is_none());
        Vec::new()
    } else if config.tx_root_region {
        tx_root_region_data = Some(if config.tier_user_tx_capacity.is_some() {
            // Tier capacity: authenticate EVERY leaf of the padded tx tree.
            // A live leaf proves its tx-body hash, a dead leaf proves the
            // ZERO padding digest — entries are live-muxed, so the binding
            // structure is class-fixed and the rim const pins are subsumed
            // (every padding leaf is authenticated as zero directly).
            tx_root_region_capacity_handoff(
                b,
                &inputs.tx_root_inputs,
                &inputs.tx_body_standard_hashes,
                &header,
                &tx_hashes,
                &live_bits,
                tx_delta,
            )
        } else {
            tx_root_region_handoff(b, &inputs.tx_root_inputs, &header, &tx_hashes)
        });
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

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: tx-root");
    // ---- exact_state component + its statement anchors. Built BEFORE the
    // authorization loop so region mode can thread its region handoff
    // (`ExactStateRegionData`) into the plural wallet-PCS discharge below;
    // its own inputs (claim/header wires) all exist by this point.
    //
    // Tier capacity: the touched-slot statement (old ++ new halves) pads
    // PER HALF to the tier's touched capacity with duplicates of each
    // half's first entry — a duplicate re-proves an already-proven leaf
    // against the same root (value-neutral), so the statement width is a
    // pure function of the tier and the leaf↔path index pairing (old half
    // `j < t`, new half `j ≥ t`) is preserved.
    let es_inputs_padded = config.tier_user_tx_capacity.map(|cap| {
        pad_exact_state_inputs_to_tier(&inputs.exact_state_killshot_inputs[0], cap)
    });
    let es_inputs_ref =
        es_inputs_padded.as_ref().unwrap_or(&inputs.exact_state_killshot_inputs[0]);
    let (exact_state, es_region_data) = build_exact_state_slot_with_config(
        b,
        es_inputs_ref,
        &proof.exact_state[0],
        config.exact_state_region,
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

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: exact-state");
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
    // Region owner-auth path (`config.owner_auth_region`): the inline per-tx
    // KSCHANNL replay is skipped; instead every tx's trace proof/inputs and
    // native objects are collected and the whole block's owner-auth killshots
    // discharge in ONE tiled data-parallel walk-C AFTER the loop
    // (transaction-count flat). That discharge produces the same PCS obligations
    // the inline replay does (which the wallet-PCS discharge consumes) plus the
    // walk-C opening claims that bind the transcript.
    let mut oa_trace_proofs: Vec<OwnerAuthProofTrace> = Vec::new();
    let mut oa_natives = Vec::new();
    let mut oa_native_inputs = Vec::new();
    // Per-tx owner / live-input counts, summed as INTEGERS after the loop (field
    // addition would be XOR -- wrong for >1 tx). At tier capacity each term is
    // GATED by the slot's liveness bit, so ghost slots contribute zero.
    let mut owner_counts: Vec<LinExpr> = Vec::new();
    let mut live_lens: Vec<LinExpr> = Vec::new();
    // Tier capacity: slots [n_real_user, n_auth_slots) are canonical GHOST
    // slots proving the protocol `ghost_authorization()` — same code path as
    // real slots (their KSCHANNL transcripts tile walk C, their capsule proofs
    // discharge in the plural), with the tx_body_hash pinned to the capacity
    // tx-hash wires (whose values ARE the ghost body hash by the spine
    // padding above).
    let ghost_auth = (n_auth_slots > n_real_user).then(noid_gkr::ghost_tx::ghost_authorization);
    for i in 0..n_auth_slots {
        let (public_native, witness_proof, hash_idx) = if i < n_real_user {
            let input = &inputs.authorization_inputs[i];
            assert_eq!(input.block_index, 0, "one block per link");
            // Native `verify_authorization_statement_proof` statement check.
            assert_eq!(input.tx_body_hash, input.public.tx_body_hash);
            (&input.public, &inputs.authorization_witnesses[i], input.tx_index)
        } else {
            let (proof, public) = ghost_auth.expect("ghost authorization derives");
            (public, proof, i + tx_delta)
        };
            if config.owner_auth_region {
            // Region path: alloc the two trace objects EXACTLY as the inline slot
            // (`build_owner_auth_slot`) does, but do NOT run the inline killshot —
            // the KSCHANNL transcript is replayed by the shared walk-C discharge
            // after the loop. The statement bindings (tx_body_hash pin, owner /
            // live-input counts) are identical to the inline path.
            let inputs_t = OwnerAuthPublicInputsTrace::alloc(b, public_native);
            let proof_t = OwnerAuthProofTrace::alloc(b, witness_proof, public_native.layout);
            if hash_idx < tx_hashes.len() {
                pin_eq2(b, &inputs_t.tx_body_hash, &tx_hashes[hash_idx]);
            } else {
                // PAD slot (the capacity rounded up to a power of two): no
                // tx slot exists past the capacity, so the body-hash pin
                // lands on the ghost-body protocol constant — the same value
                // the in-capacity ghost slots read from their tx-hash wires.
                let gh = noid_gkr::ghost_tx::ghost_tx_body_hash();
                let gw = [const_block(gh[0]), const_block(gh[1])];
                pin_eq2(b, &inputs_t.tx_body_hash, &gw);
            }
            if config.tier_user_tx_capacity.is_some() {
                owner_counts.push(mul(b, &live_bits[i], &inputs_t.owner_count));
                live_lens.push(mul(b, &live_bits[i], &inputs_t.live_len));
            } else {
                owner_counts.push(inputs_t.owner_count.clone());
                live_lens.push(inputs_t.live_len.clone());
            }
            oa_trace_proofs.push(proof_t);
            oa_natives.push(witness_proof.clone());
            oa_native_inputs.push(public_native.clone());
            // The wallet-PCS discharge still consumes each tx's capsule proof.
            region_natives.push(witness_proof.pcs.clone());
            auth_inputs.push(inputs_t);
        } else {
            // Inline per-tx owner-auth killshot replay (never at capacity:
            // the config assert requires the full region stack).
            let (inputs_t, obligation) = build_owner_auth_slot(b, witness_proof, public_native);
            if config.discharge_wallet_pcs {
                // Shape-fixed region discharge: defer to ONE tiled call below
                // (the region layer is the ONLY wallet-PCS mode).
                region_obligations.push(obligation);
                region_natives.push(witness_proof.pcs.clone());
            }
            pin_eq2(b, &inputs_t.tx_body_hash, &tx_hashes[hash_idx]);
            owner_counts.push(inputs_t.owner_count.clone());
            live_lens.push(inputs_t.live_len.clone());
            auth_inputs.push(inputs_t);
        }
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: per-tx auth allocs");
    // Region owner-auth discharge (once, after the loop): ONE tiled walk-C
    // replays all K KSCHANNL transcripts (transaction-count flat), producing the
    // SAME `PendingAuthPcsObligation`s the inline per-tx replay does plus the
    // walk-C committed-column opening claims. The obligations feed the wallet-PCS
    // discharge below UNCHANGED; the walk-C claims bind the owner-auth transcript
    // and MUST be threaded through the link IO, so they come FIRST in
    // `pending_wallet_pcs`. Requires the region wallet-PCS path so the obligations
    // are actually discharged (a complete proof).
    let mut oa_recording = None;
    if config.owner_auth_region {
        assert!(
            config.discharge_wallet_pcs,
            "owner_auth_region requires the wallet-PCS discharge (the produced obligation must be discharged)"
        );
        let (obligations, oa_claims, recording) = discharge_owner_auth_killshots_via_region(
            b,
            &oa_trace_proofs,
            &auth_inputs,
            &oa_natives,
            &oa_native_inputs,
        );
        region_obligations = obligations;
        pending_wallet_pcs.extend(oa_claims);
        // The C′ discharge transcript recording rides the wallet plural's
        // walk C (region-2 block) — the plural pins its wires there.
        oa_recording = Some(recording);
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: owner-auth walk C' discharge");
    // ONE tiled plural discharge for the whole block (region path): the K txs'
    // wallet-capsule families tile into one walk A/B/C and the returned committed-
    // column opening claims are flat in tx count, threading through the link's
    // public IO. `k` = tx count must be a power of two (the plural asserts it; a
    // tier pads its real txs to next_pow2 with ghost obligations).
    if config.discharge_wallet_pcs {
        let params = config.wallet_pcs_params;
        if config.exact_state_region || config.tx_root_region || config.spine_region {
            // The exact-state / tx-root / spine families ride the plural
            // discharge's walks; a block-bearing region class always carries
            // at least one tx, so an empty obligation set (which would skip
            // the plural and leave that hashing undischarged) is unreachable
            // by construction.
            assert!(
                !region_obligations.is_empty(),
                "exact_state_region/tx_root_region/spine_region with no wallet-PCS \
                 obligations (a block-bearing region class always has txs)"
            );
        }
            if !region_obligations.is_empty() {
            // extend (not assign): the owner-auth region path may have already
            // pushed its walk-C opening claims, which must be kept.
            pending_wallet_pcs.extend(discharge_auth_pcs_obligations_via_region(
                b,
                &region_obligations,
                &region_natives,
                params,
                es_region_data.as_ref(),
                tx_root_region_data.as_ref(),
                spine_region_data.as_ref(),
                oa_recording.as_ref(),
            ));
        }
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: wallet plural (walks A/B/C)");
    // Totals: the per-slot counts sum to the claim's resource lanes
    // (`verify_authorization_components`). The per-tx counts sum as INTEGERS
    // (ripple-carry over tower bits), NOT field addition -- GF(2^128) add is XOR,
    // so a field sum of >1 count is wrong (e.g. 1 + 1 = 0, not 2). A single-tx
    // block sums one term, reproducing the former single-count pin exactly.
    let totals = &inputs.authorization_totals;
    if config.tier_user_tx_capacity.is_some() {
        // Tier capacity: the tx-count lanes bind to the LIVENESS SUM (the
        // pin structure is class-fixed; the value is content), replacing the
        // content-shaped const pins. TX_COUNT = USER_TX_COUNT + the class's
        // non-user delta (the coinbase when carried) as an INTEGER.
        let user_sum = pin_u64_sum(b, &live_bits);
        pin_eq(b, &claim.fields[claim_layout::USER_TX_COUNT], &user_sum);
        if tx_delta == 1 {
            pin_u64_successor(b, &user_sum, &claim.fields[claim_layout::TX_COUNT]);
        } else {
            pin_eq(b, &claim.fields[claim_layout::TX_COUNT], &user_sum);
        }
    } else {
        let user_tx_count = const_block(Block128::from(totals.user_tx_count as u128));
        pin_eq(b, &claim.fields[claim_layout::USER_TX_COUNT], &user_tx_count);
        let tx_count = const_block(Block128::from(tx_hashes.len() as u128));
        pin_eq(b, &claim.fields[claim_layout::TX_COUNT], &tx_count);
    }
    let live_sum = pin_u64_sum(b, &live_lens);
    pin_eq(b, &claim.fields[claim_layout::LIVE_INPUT_COUNT], &live_sum);
    let owner_total = alloc_block(b, Block128::from(totals.owner_count_total as u128));
    let owner_sum = pin_u64_sum(b, &owner_counts);
    pin_eq(b, &owner_total, &owner_sum);

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: count sums");
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

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: claim fold + checkpoint");

    BlockSlots {
        header,
        claim,
        start_acc,
        end_acc,
        spine_inputs,
        tx_hashes,
        tx_root_paths,
        auth_inputs,
        live_bits,
        exact_state,
        pending_wallet_pcs,
    }
}

/// The region opening claims' native `(point, value)` per claim, in
/// [`BlockSlots::pending_wallet_pcs`] ORDER, via a lightweight scratch discharge
/// over ONLY the owner-auth slots + the region discharge(s) — SKIPPING the
/// block-[B] killshots (~2.7M wires @1 tx), which do not affect the region
/// native values.
///
/// The link fills its public-IO envelope from these BEFORE the real trace
/// allocates the fixed-position IO cells; the claim WIRES + committed-column
/// SLICES come from the real (full) build. The region native `(point, value)`
/// are driven solely by each tx's owner-auth obligation (`commitment_cap_lanes`
/// + `reduction`) and — with `owner_auth_region` — the class-fixed KSCHANNL
/// channel schedule, both content-determined and independent of the wire
/// positions / the [B] killshots, so the values here are identical to the
/// full-block build (only the committed-column slices differ, supplied by the
/// real build). This is what lets the link recover the IO values without
/// building the whole block slots twice.
///
/// `owner_auth_region` MUST match the real build's
/// [`BlockSlotsConfig::owner_auth_region`]: when true, the walk-C owner-auth
/// opening claims precede the wallet-PCS claims (mirroring the real build's
/// `pending_wallet_pcs` ordering), and the wallet-PCS obligations are produced
/// by the SAME scratch owner-auth region discharge (parity with the inline
/// obligations is separately gated).
///
/// `exact_state_region` MUST likewise match the real build's flag: when true,
/// a scratch exact-state region handoff (fresh wires, same native values) is
/// threaded into the plural discharge, so the walk-A/B columns — hence every
/// native claim `(point, value)` — mirror the real build exactly.
/// `tx_root_region` is the same contract for the tx-root walk-B leg, and
/// `spine_region` for the walk-A spine tile+tree families.
pub fn region_wallet_pcs_native(
    inputs: &AcceptedBlockBatchComponentInputs,
    params: RegionDischargeParams,
    owner_auth_region: bool,
    exact_state_region: bool,
    tx_root_region: bool,
    spine_region: bool,
    tier_user_tx_capacity: Option<usize>,
) -> Vec<(Vec<F128>, F128)> {
    if inputs.authorization_inputs.is_empty() {
        return Vec::new();
    }
    assert!(
        tier_user_tx_capacity.is_none() || (owner_auth_region && spine_region && tx_root_region),
        "tier capacity requires the full region stack"
    );
    let mut pb = FieldR1csBuilder::new();
    let mut out: Vec<(Vec<F128>, F128)> = Vec::new();
    // The capacity view of the block's tx lists (mirror of the real build):
    // real bodies/proofs first, then the protocol ghost slots.
    let n_real_user = inputs.authorization_inputs.len();
    let n_real_txs = inputs.tx_body_standard_inputs.len();
    let tx_delta = n_real_txs.saturating_sub(n_real_user);
    let n_auth_slots = tier_auth_slot_count(tier_user_tx_capacity, n_real_user);
    let cap_txs = tier_user_tx_capacity.map_or(n_real_txs, |c| c + tx_delta);
    let mut spine_natives: Vec<SpineInputs> = inputs.tx_body_standard_inputs.clone();
    let mut hash_natives: Vec<[Block128; 2]> = inputs.tx_body_standard_hashes.clone();
    if cap_txs > n_real_txs {
        let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
        let ghost_spine = noid_gkr::spine_statement::spine_inputs_from_body(&ghost_body)
            .expect("the canonical ghost body has spine inputs");
        let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
        for _ in n_real_txs..cap_txs {
            spine_natives.push(ghost_spine.clone());
            hash_natives.push(ghost_hash);
        }
    }
    let es_padded = tier_user_tx_capacity
        .map(|cap| pad_exact_state_inputs_to_tier(&inputs.exact_state_killshot_inputs[0], cap));
    let scratch_es = exact_state_region.then(|| {
        scratch_exact_state_region_data(
            &mut pb,
            es_padded.as_ref().unwrap_or(&inputs.exact_state_killshot_inputs[0]),
        )
    });
    let scratch_txr = (tx_root_region && !inputs.tx_root_inputs.is_empty()).then(|| {
        if tier_user_tx_capacity.is_some() {
            // Throwaway wires carrying the same natives: root, capacity
            // tx-hash wires, constant liveness bits.
            let root_native = inputs.tx_root_inputs[0].expected_root;
            let root_w =
                [alloc_block(&mut pb, root_native[0]), alloc_block(&mut pb, root_native[1])];
            let tx_hash_ws: Vec<[LinExpr; 2]> = hash_natives
                .iter()
                .map(|h| std::array::from_fn(|i| alloc_block(&mut pb, h[i])))
                .collect();
            let live: Vec<LinExpr> = (0..n_auth_slots)
                .map(|i| {
                    let v = Block128::from(if i < n_real_user { 1u128 } else { 0u128 });
                    alloc_block(&mut pb, v)
                })
                .collect();
            tx_root_region_capacity_data_from_wires(
                &mut pb,
                &inputs.tx_root_inputs,
                &inputs.tx_body_standard_hashes,
                root_w,
                &tx_hash_ws,
                &live,
                tx_delta,
            )
        } else {
            scratch_tx_root_region_data(&mut pb, &inputs.tx_root_inputs)
        }
    });
    let scratch_spine = (spine_region && !inputs.tx_body_standard_inputs.is_empty())
        .then(|| scratch_spine_region_data(&mut pb, &spine_natives, &hash_natives));
    // Produce the wallet-PCS obligations + natives the SAME way the real build
    // does for this `owner_auth_region` mode: the capacity view appends the
    // protocol ghost authorization to the real per-tx lists.
    let mut oa_recording = None;
    let (obligations, natives) = if owner_auth_region {
        // Scratch owner-auth region discharge (mirror of the real build): its
        // walk-C opening claims come FIRST in `pending_wallet_pcs`, so prefill
        // their natives before the wallet-PCS claims below.
        let ghost_auth =
            (n_auth_slots > n_real_user).then(noid_gkr::ghost_tx::ghost_authorization);
        let slot_native = |i: usize| -> (&noid_gkr::owner_auth::OwnerAuthPublicInputs,
                                          &noid_gkr::OwnerAuthProofKillShot) {
            if i < n_real_user {
                (
                    &inputs.authorization_inputs[i].public,
                    &inputs.authorization_witnesses[i],
                )
            } else {
                let (proof, public) = ghost_auth.expect("ghost authorization derives");
                (public, proof)
            }
        };
        let oa_trace_proofs: Vec<OwnerAuthProofTrace> = (0..n_auth_slots)
            .map(|i| {
                let (public, wp) = slot_native(i);
                OwnerAuthProofTrace::alloc(&mut pb, wp, public.layout)
            })
            .collect();
        let oa_trace_inputs: Vec<OwnerAuthPublicInputsTrace> = (0..n_auth_slots)
            .map(|i| OwnerAuthPublicInputsTrace::alloc(&mut pb, slot_native(i).0))
            .collect();
        let oa_natives: Vec<_> = (0..n_auth_slots).map(|i| slot_native(i).1.clone()).collect();
        let oa_native_inputs: Vec<_> =
            (0..n_auth_slots).map(|i| slot_native(i).0.clone()).collect();
        let (obligations, oa_claims, recording) = discharge_owner_auth_killshots_via_region(
            &mut pb,
            &oa_trace_proofs,
            &oa_trace_inputs,
            &oa_natives,
            &oa_native_inputs,
        );
        oa_recording = Some(recording);
        for c in &oa_claims {
            out.push((c.native_point.clone(), c.native_value));
        }
        let natives: Vec<_> =
            (0..n_auth_slots).map(|i| slot_native(i).1.pcs.clone()).collect();
        (obligations, natives)
    } else {
        // Inline per-tx owner-auth obligations.
        let mut obligations = Vec::new();
        let mut natives = Vec::new();
        for (input, witness_proof) in inputs
            .authorization_inputs
            .iter()
            .zip(inputs.authorization_witnesses.iter())
        {
            let (_inputs_t, obligation) =
                build_owner_auth_slot(&mut pb, witness_proof, &input.public);
            obligations.push(obligation);
            natives.push(witness_proof.pcs.clone());
        }
        (obligations, natives)
    };
    if obligations.is_empty() {
        return out;
    }
    // ONE tiled plural wallet-PCS discharge -- the same call the real block-slots
    // build makes. The region `(point, value)` depend only on each tx's
    // obligation + native proof + the block's exact-state natives (not on the
    // wire positions or the [B] killshots), so they are identical to the full
    // build; only the committed-column SLICES differ (the link takes those from
    // the real build).
    for c in discharge_auth_pcs_obligations_via_region(
        &mut pb,
        &obligations,
        &natives,
        params,
        scratch_es.as_ref(),
        scratch_txr.as_ref(),
        scratch_spine.as_ref(),
        oa_recording.as_ref(),
    ) {
        out.push((c.native_point, c.native_value));
    }
    out
}
