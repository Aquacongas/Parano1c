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
//! - the direct ten-lane accumulator transition shares the header block-id,
//!   parent-tip, state/depth/counter and height wires; transaction epoch is
//!   selected by a constrained `height mod 144` relation;
//! - every tx-root Merkle path pins its root to the underlying universal
//!   256-leaf Merkle root `M`, its leaf to the spine slot's tx-body hash, its
//!   direction bits to the
//!   CONSTANT bits of its tx position, and the last real path pins its
//!   right-hand siblings to the canonical zero-subtree digests (the padding
//!   rim the native root reconstruction binds); a domain-separated
//!   `TAG_TXROOT(M, tx_count)` wrapper then pins to the header `tx_root`;
//! - each owner-auth slot pins its `tx_body_hash` to the spine hash of its
//!   tx and discharges its wallet-PCS obligation; the authorization totals
//!   are pinned to the per-slot counts AND to the claim's resource fields;
//! - production exact state derives a fixed-capacity paired local/upper walk
//!   from the sibling-only structural carrier. Slot-sorted action leaves and
//!   all 32 slot bits bind its entries/directions; local and segment chains
//!   end at the parent/grown-parent and child header roots selected by the
//!   header-bound dynamic depth.
//! - each user's selected input/output amounts obey checked conservation; the
//!   same selected bitmap bits drive minimum fee and deterministic burn under
//!   parent occupancy, and the mandatory coinbase is bounded by child-depth
//!   reward plus the checked 72-bit claimable-fee aggregate.
//!
//! NOT bound here (audited residue, each correctly scoped to another
//! layer, none a hole in what this file claims):
//! - the parent header's `active_slot_count` / `alloc_counter`: CLOSED —
//!   the accumulator boundary carries both counters as lanes; each block
//!   pins its start counters to the claim's PARENT section and its end
//!   direct boundary to the verified header, and the link chain rule
//!   `start == prev.end` closes the chain. Header PoW/ASERT/MTP fields
//!   (timestamp, miner, nonce, target) are deliberately out of π's
//!   scope — a fresh peer validates its own header chain.
//! - shared-region column algebra must be discharged by the post-commit
//!   sidecar: its relation challenges are sampled only after the outer witness
//!   commitment. The older in-builder A/B/C/D transcript twins are retained
//!   temporarily during that migration, but are not production proof
//!   authority because their columns were not committed before their local
//!   Fiat--Shamir draws.
//!
//! The direct rows in this assembly bind authorization, action routing,
//! exact-state transition, continuity, and checked monetary arithmetic. A
//! production proof additionally requires the post-commit region sidecar to
//! make the shared hashing-column reductions sound.

use noid_core::hardware::flat_to_tower_u128;
use noid_core::Block128;
use noid_poseidon2b::native::compression::compress;
use noid_poseidon2b::native::domain::TAG_TXROOT;

use super::trace::accepted_claim_batch::{
    build_direct_accumulator_transition_slot, compress_with_tag_trace, digest_lanes,
    AccumulatorWires, DirectChildWires,
};
use super::trace::accepted_claim_hash::{
    build_accepted_claim_hash_slot, AcceptedClaimHashInputsTrace,
};
use super::trace::action_compaction::{
    bind_mint_packed_values_body_order, compact_action_rows, CompactedActionTrace,
};
use super::trace::action_surface::{
    bind_coinbase_action_with_amount, bind_user_action_surface, ActionRowTrace,
};
use super::trace::checkpoint_poseidon::{
    build_checkpoint_poseidon_slot_with_inputs, HeaderHashInputsTrace,
};
use super::trace::exact_state::{
    bind_actions_to_exact_state_leaves, bind_exact_state_header_roots_dynamic,
    bind_structural_frontier_count_from_actions_dynamic, build_exact_state_structural_region_slot,
    select_upper_paired_roots, ExactStateSlotWires, PairedRootCellPair, StateDepthTrace,
};
use super::trace::fee_arithmetic::bind_block_fee_arithmetic;
use super::trace::public_arithmetic::{bind_user_public_arithmetic, UserPublicArithmeticTrace};
use super::trace::region_source_binding::{
    PairedExactStateCells, SpineInstanceRegion, SpineRegionData, TxRootPathRegion, TxRootRegionData,
};
use super::trace::segment_compaction::{bind_segment_upper_chain, compact_segment_updates};
use super::trace::tx_body_spine::SpineInputsTrace;
use super::trace::zk_authorization_candidate::{
    bind_selected_zk_block_region, SelectedZkAuthorizationProofBundle, SelectedZkBlockRegionBinding,
};
use super::trace::{
    alloc_block, const_block, flat_const, flat_of, integer_add_no_overflow, mul, pin_eq,
    pin_lt_strict, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr, RawChannelTrace, Wire,
    F128,
};
use crate::accumulator::ChainAccumulator;
use crate::block_certificate_backend::{
    AcceptedBlockBatchComponentInputs, AcceptedBlockBatchComponentProof,
};
use crate::pow_header::header_hash_proof_inputs;
#[cfg(feature = "selected-zk-measurement")]
use crate::region_sidecar::BlockRegionSidecarVk;
use noid_gkr::SpineInputs;
use noid_ivc_core::deep_chain::spine::SpineInstanceFlat;
use noid_ivc_core::field_circuit::f128_to_u128;

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

#[cfg(test)]
mod selected_zk_capability_tests {
    use super::*;

    #[test]
    fn b255_capability_is_zero_row_exact_and_pad_is_constant_metadata() {
        let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
        let ghost_statement = noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
            tx_body_hash: noid_gkr::ghost_tx::ghost_tx_body_hash(),
            address: ghost_body.input_owner.as_fields(),
        };
        for live_count in [0usize, 1, 17, 254, 255] {
            let (b, capability) = canonical_selected_zk_authorization_fixture(live_count);
            assert_eq!(capability.len(), 256);
            assert_eq!(capability.live_count(), live_count);
            for index in 0..255 {
                let slot = capability.slot(index);
                assert!(slot.body_aliases().is_some());
                assert_eq!(
                    slot.kind(),
                    if index < live_count {
                        CanonicalSelectedZkAuthorizationSlotKind::Live
                    } else {
                        CanonicalSelectedZkAuthorizationSlotKind::Ghost
                    }
                );
                assert_eq!(
                    slot.liveness().eval(b.values()),
                    if index < live_count {
                        F128::ONE
                    } else {
                        F128::ZERO
                    }
                );
            }
            let pad = capability.slot(255);
            assert_eq!(pad.kind(), CanonicalSelectedZkAuthorizationSlotKind::Pad255);
            assert!(pad.body_aliases().is_none());
            assert_eq!(pad.liveness().eval(b.values()), F128::ZERO);
            assert_eq!(pad.native_statement(), ghost_statement);
        }
    }

    #[test]
    fn selected_capability_uses_each_canonical_class_capacity() {
        for tier in [8usize, 32, 64, 255] {
            let geometry = crate::region_sidecar::selected_zk_block_geometry(tier).unwrap();
            for live_count in [0usize, tier] {
                let (b, capability) =
                    canonical_selected_zk_authorization_fixture_for_tier(tier, live_count);
                assert_eq!(capability.len(), geometry.auth_tiles);
                assert_eq!(capability.live_count(), live_count);
                for index in 0..tier {
                    assert!(capability.slot(index).body_aliases().is_some());
                    assert_eq!(
                        capability.slot(index).liveness().eval(b.values()),
                        if index < live_count {
                            F128::ONE
                        } else {
                            F128::ZERO
                        }
                    );
                }
                if tier == 255 {
                    assert_eq!(
                        capability.slot(255).kind(),
                        CanonicalSelectedZkAuthorizationSlotKind::Pad255
                    );
                    assert!(capability.slot(255).body_aliases().is_none());
                } else {
                    assert_eq!(capability.len(), tier);
                    assert!(capability.slot(tier - 1).body_aliases().is_some());
                }
            }
        }
    }

    #[test]
    fn capability_carrier_has_no_clone_or_raw_constructor_surface() {
        let source = include_str!("block_slots.rs");
        let capability_name = ["CanonicalSelectedZkAuthorization", "Capability"].concat();
        let declaration_marker = format!("struct {capability_name}");
        let declaration = source
            .split(&declaration_marker)
            .nth(1)
            .expect("capability declaration");
        let header = declaration.split('}').next().expect("capability header");
        assert!(!header.contains("pub "), "capability field became public");
        assert!(!source.contains(&format!("impl Clone for {capability_name}")));
        let raw_constructor =
            ["fn new_canonical_selected_zk_", "authorization_capability"].concat();
        assert!(!source.contains(&raw_constructor));
        let free_take = ["fn take_selected_zk_", "authorization_capability"].concat();
        assert!(!source.contains(&free_take));
    }

    #[test]
    fn selected_declared_count_is_a_zero_row_canonical_bitmap_hint() {
        for expected in 1u8..=noid_gkr::MAX_AUTHORIZATION_LIVE_INPUTS {
            let mut body = noid_gkr::ghost_tx::ghost_tx_body();
            let output_bits = body.validity_bitmap & !((1u16 << noid_tx::TX_INPUTS) - 1);
            body.validity_bitmap = output_bits | ((1u16 << expected) - 1);
            let native = noid_gkr::spine_statement::spine_inputs_from_body(&body);
            let mut b = FieldR1csBuilder::new();
            let spine = SpineInputsTrace::alloc(&mut b, &native);
            let before = b.num_wires();
            assert_eq!(selected_declared_live_input_count(&b, &spine), expected);
            assert_eq!(
                b.num_wires(),
                before,
                "native bitmap hint must not add rows"
            );
        }
    }

    #[test]
    fn canonical_builder_has_no_runtime_authorization_backend_and_preserves_column_order() {
        let source = include_str!("block_slots.rs");
        let backend_type = ["BlockAuthorization", "Backend"].concat();
        let configurable_builder = ["build_block_slots", "_with_config"].concat();
        assert!(!source.contains(&backend_type));
        assert!(!source.contains(&configurable_builder));
        let core = source
            .rsplit("fn build_selected_zk_block_slots_core")
            .next()
            .expect("canonical private authorization core");

        let fee = core
            .find("bind_block_fee_arithmetic")
            .expect("common fee arithmetic");
        let selected_region = core
            .find("let selected_region = Some(bind_selected_zk_block_region")
            .expect("selected region bridge");
        assert!(
            fee < selected_region,
            "selected columns moved before the frozen fee-row prefix"
        );
        assert_eq!(
            core.matches("mint_canonical_selected_zk_authorization_capability")
                .count(),
            1,
            "selected capability must be minted once inside the canonical core"
        );
    }
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

const _: () =
    assert!(claim_layout::FIELDS == noid_gkr::accepted_claim_killshot::ACCEPTED_CLAIM_FIELDS);
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

/// Prove `parent + mints = child + spends` over unsigned u64 integers.
/// Both sides reject overflow; the scalar inputs are range-checked by the
/// adders rather than interpreted as characteristic-two XOR sums.
fn bind_active_slot_counter_delta(
    b: &mut FieldR1csBuilder,
    parent: &LinExpr,
    child: &LinExpr,
    spends: &LinExpr,
    mints: &LinExpr,
) {
    let parent_plus_mints = integer_add_no_overflow(b, parent, mints, 64);
    let child_plus_spends = integer_add_no_overflow(b, child, spends, 64);
    pin_eq(b, &parent_plus_mints, &child_plus_spends);
}

/// Close the production exact-state relation from the slot-sorted action
/// prefix through the paired local/upper Merkle walks to the header-bound
/// old/new roots.
fn bind_paired_exact_state_transition(
    b: &mut FieldR1csBuilder,
    actions: &CompactedActionTrace,
    exact_state: &ExactStateSlotWires,
    paired: &PairedExactStateCells,
    child_depth: &StateDepthTrace,
) {
    let touched_capacity = actions.rows.len();
    assert_eq!(exact_state.slot_leaves.len(), 2 * touched_capacity);
    assert_eq!(paired.local.len(), touched_capacity);
    assert!(!paired.upper.is_empty());
    assert!(paired.upper.len() <= touched_capacity);

    let (old_leaves, new_leaves) = exact_state.slot_leaves.split_at(touched_capacity);
    bind_actions_to_exact_state_leaves(b, &actions.rows, old_leaves, new_leaves);

    let mut local_before = Vec::with_capacity(touched_capacity);
    let mut local_after = Vec::with_capacity(touched_capacity);
    for index in 0..touched_capacity {
        let cells = &paired.local[index];
        pin_eq2(b, &old_leaves[index].expected_leaf, &cells.old_entry);
        pin_eq2(b, &new_leaves[index].expected_leaf, &cells.new_entry);
        for level in 0..16 {
            pin_eq(
                b,
                &cells.directions[level],
                &LinExpr::from_wire(actions.slot_bits[index][level]),
            );
        }
        local_before.push(cells.old_root.clone());
        local_after.push(cells.new_root.clone());
    }

    let segments = compact_segment_updates(
        b,
        &actions.rows,
        &actions.slot_bits,
        &actions.adjacent_msb_one_hot,
        &actions.adjacent_both_live,
        &local_before,
        &local_after,
        paired.upper.len(),
    );

    let mut upper_old_entries = Vec::with_capacity(paired.upper.len());
    let mut upper_new_entries = Vec::with_capacity(paired.upper.len());
    let mut upper_before = Vec::with_capacity(paired.upper.len());
    let mut upper_after = Vec::with_capacity(paired.upper.len());
    for (index, cells) in paired.upper.iter().enumerate() {
        for level in 0..16 {
            pin_eq(
                b,
                &cells.directions[level],
                &LinExpr::from_wire(segments.segment_id_bits[index][level]),
            );
        }
        let roots_by_depth: [PairedRootCellPair; 16] = std::array::from_fn(|level| {
            [
                cells.old_roots[level].clone(),
                cells.new_roots[level].clone(),
            ]
        });
        let selected = select_upper_paired_roots(b, child_depth, &roots_by_depth);
        upper_old_entries.push(cells.old_entry.clone());
        upper_new_entries.push(cells.new_entry.clone());
        upper_before.push(selected[0].clone());
        upper_after.push(selected[1].clone());
    }

    bind_segment_upper_chain(
        b,
        &segments,
        &upper_old_entries,
        &upper_new_entries,
        &upper_before,
        &upper_after,
        &exact_state.roots.old_root,
        &exact_state.roots.new_root,
    );
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
                acc = integer_add_no_overflow(b, &acc, t, N);
            }
            acc
        }
    }
}

fn append_user_action_surface(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    tx_live: &LinExpr,
    expected_owner: &[LinExpr; 2],
    declared_live_inputs: u8,
    candidates: &mut Vec<ActionRowTrace>,
    input_selectors: &mut Vec<LinExpr>,
    output_selectors: &mut Vec<LinExpr>,
) -> UserPublicArithmeticTrace {
    let surface = bind_user_action_surface(b, spine, tx_live, expected_owner);
    let arithmetic = bind_user_public_arithmetic(b, spine, &surface);
    let declared = alloc_declared_live_input_count(b, declared_live_inputs);
    let selected_declared = mul(b, tx_live, &declared);
    pin_eq(b, &arithmetic.live_input_count, &selected_declared);
    input_selectors.extend(surface.selected_inputs.iter().cloned());
    output_selectors.extend(surface.selected_outputs.iter().cloned());
    candidates.extend(surface.ordered_rows());
    arithmetic
}

/// Recover only the native value hint for the existing fixed-shape declared
/// input-count relation.  The hint adds no rows and carries no authority: the
/// action surface range-checks the canonical L15 bitmap, public arithmetic
/// recomputes its selected popcount, and `append_user_action_surface` pins that
/// result to the freshly allocated 1..=8 count.
fn selected_declared_live_input_count(b: &FieldR1csBuilder, spine: &SpineInputsTrace) -> u8 {
    use noid_tx::body_hash::TX8X2_LEAF_FLAGS;

    let flat = f128_to_u128(spine.leaves[TX8X2_LEAF_FLAGS][0].eval(b.values()));
    let bitmap = flat_to_tower_u128(flat);
    let input_mask = (1u128 << noid_tx::TX_INPUTS) - 1;
    let count = (bitmap & input_mask).count_ones() as u8;
    assert!(
        (1..=noid_gkr::MAX_AUTHORIZATION_LIVE_INPUTS).contains(&count),
        "selected user bitmap must contain 1..=8 live inputs"
    );
    count
}

/// Allocate the native authorization count and pin it to bitmap popcount in
/// [`append_user_action_surface`]. Keep the relation class-fixed while
/// enforcing the serialized boundary 1..=8.
fn alloc_declared_live_input_count(b: &mut FieldR1csBuilder, count: u8) -> LinExpr {
    assert!((1..=noid_gkr::MAX_AUTHORIZATION_LIVE_INPUTS).contains(&count));
    const BITS: usize = 4;
    let count = alloc_block(b, Block128::from(count as u128));
    let count_bits = range_check_bits(b, &count, BITS);
    let zero_bits = range_check_bits(b, &const_block(Block128::from(0u128)), BITS);
    pin_lt_strict(b, &zero_bits, &count_bits);
    let cap_plus_one = const_block(Block128::from(
        noid_gkr::MAX_AUTHORIZATION_LIVE_INPUTS as u128 + 1,
    ));
    let cap_plus_one_bits = range_check_bits(b, &cap_plus_one, BITS);
    pin_lt_strict(b, &count_bits, &cap_plus_one_bits);
    count
}

fn pin_pair_at(b: &mut FieldR1csBuilder, fields: &[LinExpr], at: usize, to: &[LinExpr; 2]) {
    pin_eq(b, &fields[at], &to[0]);
    pin_eq(b, &fields[at + 1], &to[1]);
}

/// Bind the universal 256-leaf Merkle root and real transaction count to the
/// header's domain-separated transaction root.
fn bind_tx_root_count_wrapper(
    b: &mut FieldR1csBuilder,
    merkle_root: &[LinExpr; 2],
    tx_count: &LinExpr,
    header_root: &[LinExpr; 2],
) {
    let count_digest = [tx_count.clone(), LinExpr::zero()];
    let wrapped = compress_with_tag_trace(b, TAG_TXROOT, merkle_root, &count_digest);
    pin_eq2(b, &wrapped, header_root);
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
        level = level
            .chunks_exact(2)
            .map(|p| compress(&p[0], &p[1]))
            .collect();
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
    tx_hashes: &[[LinExpr; 2]],
    live_bits: &[LinExpr],
    tx_delta: usize,
) -> TxRootRegionData {
    let root_native = tx_root_inputs[0].expected_root;
    let root_w = [
        alloc_block(b, root_native[0]),
        alloc_block(b, root_native[1]),
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
/// real build passes the underlying universal-tree root `M` + statement liveness; the scratch
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
    assert!(
        !tx_root_inputs.is_empty(),
        "tx-root region handoff without paths"
    );
    let depth = tx_root_inputs[0].active_depth;
    let n_leaves = 1usize << depth;
    let n_real = real_hashes.len();
    assert!(n_real >= 1 && n_real <= n_leaves);
    assert_eq!(depth, noid_chain::tx_tree::TX_TREE_DEPTH);
    assert!(tx_hashes.len() <= n_leaves);
    let root_native = tx_root_inputs[0].expected_root;
    let root_flat = [flat_of(root_native[0]), flat_of(root_native[1])];
    for lane in 0..2 {
        assert_eq!(
            root_w[lane].eval(b.values()),
            root_flat[lane],
            "Merkle root wire != the killshot statement root"
        );
    }
    let levels = padded_tx_tree_levels(real_hashes, depth);
    // Cross-check the rebuilt root against the killshot statement.
    assert_eq!(
        digest_lanes(&levels[depth][0]),
        root_native,
        "rebuilt padded tree root"
    );

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
            TxRootPathRegion {
                entry_w,
                entry_flat,
                siblings,
            }
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
    tier_user_tx_capacity.map_or(n_real_user, |tier| {
        super::shape::ShapeClass { tier }.authorization_capacity()
    })
}

/// Exact-state class capacities used by both the real region build and its
/// native claim mirror. Tier builds are content-invariant. Transitional
/// non-tier region tests use their exact touched/segment counts.
fn exact_state_region_capacities(
    structural: &crate::block_certificate_backend::ExactStateStructuralFrontierInputs,
    user_tier: Option<usize>,
) -> (usize, usize) {
    if let Some(tier) = user_tier {
        let class = super::shape::ShapeClass { tier };
        return (class.touched_capacity(), class.segment_capacity());
    }

    let touched = structural.touched_indices.len();
    let segments = structural
        .touched_indices
        .iter()
        .map(|slot| slot >> noid_chain::consensus::params::LOG_SEGMENT_SIZE)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert!(touched > 0, "exact-state transition has no touched slots");
    assert!(
        segments > 0,
        "exact-state transition has no touched segments"
    );
    (touched, segments)
}

/// The flat image of one native `SpineInputs` statement (φ lane by lane).
fn spine_instance_flat(n: &SpineInputs) -> SpineInstanceFlat {
    SpineInstanceFlat {
        leaves: std::array::from_fn(|leaf| {
            std::array::from_fn(|lane| flat_of(n.leaves[leaf][lane]))
        }),
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
    assert_eq!(
        natives.len(),
        inputs_t.len(),
        "one wire set per spine instance"
    );
    assert_eq!(
        natives.len(),
        native_hashes.len(),
        "one hash per spine instance"
    );
    assert_eq!(
        natives.len(),
        tx_hashes.len(),
        "one hash wire pair per instance"
    );
    let assert_pair = |w: &[LinExpr; 2], n: &[Block128; 2], what: &str| {
        for lane in 0..2 {
            assert_eq!(
                w[lane].eval(b.values()),
                flat_of(n[lane]),
                "{what} lane {lane}"
            );
        }
    };
    let instances = natives
        .iter()
        .zip(native_hashes.iter())
        .zip(inputs_t.iter().zip(tx_hashes.iter()))
        .map(|((n, h), (t, hw))| {
            for (leaf, pair) in t.leaves.iter().enumerate() {
                for lane in 0..2 {
                    assert_eq!(
                        pair[lane].eval(b.values()),
                        flat_of(n.leaves[leaf][lane]),
                        "spine raw leaf wire L{leaf}[{lane}]"
                    );
                }
            }
            assert_pair(hw, h, "spine tx hash");
            SpineInstanceRegion {
                flat: spine_instance_flat(n),
                leaves_w: t.leaves.clone(),
                tx_hash_w: hw.clone(),
                tx_hash_flat: [flat_of(h[0]), flat_of(h[1])],
            }
        })
        .collect();
    SpineRegionData { instances }
}

/// Bind the Tx8x2 L0 domain anchor for every real body and fix every padded
/// body to the complete canonical ghost statement.
fn bind_tx_epoch_anchors(
    b: &mut FieldR1csBuilder,
    start: &AccumulatorWires,
    spine_inputs: &[SpineInputsTrace],
    n_real_txs: usize,
    tx_delta: usize,
    capacity_live_bits: Option<&[LinExpr]>,
) {
    assert!(tx_delta <= 1);
    assert!(n_real_txs <= spine_inputs.len());
    assert!(tx_delta <= n_real_txs);
    const L0: usize = noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR;

    if tx_delta == 1 {
        for lane in 0..2 {
            pin_eq(
                b,
                &spine_inputs[0].leaves[L0][lane],
                &start.tip_block_id[lane],
            );
        }
    }
    match capacity_live_bits {
        None => {
            assert_eq!(n_real_txs, spine_inputs.len());
            for spine in &spine_inputs[tx_delta..] {
                for lane in 0..2 {
                    pin_eq(b, &spine.leaves[L0][lane], &start.epoch_anchor_id[lane]);
                }
            }
        }
        Some(live_bits) => {
            assert_eq!(spine_inputs.len(), tx_delta + live_bits.len());
            let ghost = noid_gkr::spine_statement::spine_inputs_from_body(
                &noid_gkr::ghost_tx::ghost_tx_body(),
            );
            // Every capacity slot gets the exact same rows. `live` selects a
            // real user epoch anchor; `1+live` selects the complete canonical
            // ghost body. No branch depends on the block's real tx count.
            for (spine, live) in spine_inputs[tx_delta..].iter().zip(live_bits) {
                for lane in 0..2 {
                    let epoch_diff = spine.leaves[L0][lane].add(&start.epoch_anchor_id[lane]);
                    let gated = mul(b, live, &epoch_diff);
                    pin_zero(b, &gated);
                }
                let dead = live.add_const(F128::ONE);
                for leaf in 0..noid_tx::body_hash::BODY_HASH_LEAVES {
                    for lane in 0..2 {
                        let ghost_diff =
                            spine.leaves[leaf][lane].add(&const_block(ghost.leaves[leaf][lane]));
                        let gated = mul(b, &dead, &ghost_diff);
                        pin_zero(b, &gated);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// Canonical role of one selected authorization slot. The role is
/// derived from the already boolean, monotone Block liveness prefix; callers
/// cannot supply or mutate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::acceptance) enum CanonicalSelectedZkAuthorizationSlotKind {
    Live,
    Ghost,
    Pad255,
}

/// One statement/liveness tuple owned by the canonical Block relation.
/// Fields stay private to this module: the selected all-tiles assembly can
/// borrow only the audited views below, never construct a raw statement.
pub(in crate::acceptance) struct CanonicalSelectedZkAuthorizationSlot {
    tx_body_hash: Option<[LinExpr; 2]>,
    expected_address: Option<[LinExpr; 2]>,
    liveness: LinExpr,
    native_statement: noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement,
    kind: CanonicalSelectedZkAuthorizationSlotKind,
}

impl CanonicalSelectedZkAuthorizationSlot {
    pub(in crate::acceptance) fn body_aliases(&self) -> Option<(&[LinExpr; 2], &[LinExpr; 2])> {
        self.tx_body_hash
            .as_ref()
            .zip(self.expected_address.as_ref())
    }

    pub(in crate::acceptance) fn liveness(&self) -> &LinExpr {
        &self.liveness
    }

    pub(in crate::acceptance) fn native_statement(
        &self,
    ) -> noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
        self.native_statement
    }

    pub(in crate::acceptance) fn kind(&self) -> CanonicalSelectedZkAuthorizationSlotKind {
        self.kind
    }
}

/// Non-Clone statement authority minted only by `BlockSlots` after
/// boolean/monotone liveness, complete dead-body ghost pins and PAD255=0 are
/// already in the same matrix. It intentionally has no raw constructor or
/// statement-Vec extractor. Builder affinity comes from the private owning
/// selected assembly choke point, not from this carrier by itself.
pub(in crate::acceptance) struct CanonicalSelectedZkAuthorizationCapability {
    slots: Vec<CanonicalSelectedZkAuthorizationSlot>,
}

impl CanonicalSelectedZkAuthorizationCapability {
    pub(in crate::acceptance) fn len(&self) -> usize {
        self.slots.len()
    }

    pub(in crate::acceptance) fn slot(
        &self,
        index: usize,
    ) -> &CanonicalSelectedZkAuthorizationSlot {
        &self.slots[index]
    }

    pub(in crate::acceptance) fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.kind == CanonicalSelectedZkAuthorizationSlotKind::Live)
            .count()
    }
}

fn block_from_alias(b: &FieldR1csBuilder, expression: &LinExpr) -> Block128 {
    let flat = f128_to_u128(expression.eval(b.values()));
    Block128::from(flat_to_tower_u128(flat))
}

/// Zero-row extraction of one exact selected-class statement surface. Body
/// slots retain the original Block aliases. B255's PAD has no body, so this
/// capability carries only its native protocol constants; the owning
/// selected assembly later materializes and pins the four PAD wires in its
/// still-owned builder.
fn mint_canonical_selected_zk_authorization_capability(
    b: &FieldR1csBuilder,
    tx_hashes: &[[LinExpr; 2]],
    spine_inputs: &[SpineInputsTrace],
    live_bits: &[LinExpr],
) -> CanonicalSelectedZkAuthorizationCapability {
    use noid_tx::body_hash::TX8X2_LEAF_INPUT_OWNER;

    const TX_DELTA: usize = 1;
    let body_auth_slots = spine_inputs
        .len()
        .checked_sub(TX_DELTA)
        .expect("selected class includes coinbase spine");
    let auth_slots = live_bits.len();
    let geometry = crate::region_sidecar::selected_zk_block_geometry_for_auth_tiles(auth_slots)
        .expect("selected authorization capacity is canonical");
    assert_eq!(body_auth_slots, geometry.tier);
    assert_eq!(auth_slots, geometry.auth_tiles);

    assert_eq!(tx_hashes.len(), TX_DELTA + body_auth_slots);
    if auth_slots > body_auth_slots {
        assert_eq!(geometry.tier, 255, "only B255 has an authorization PAD");
        assert_eq!(live_bits[auth_slots - 1].eval(b.values()), F128::ZERO);
    }

    let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
    let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
    let ghost_address = ghost_body.input_owner.as_fields();
    let ghost_statement = noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
        tx_body_hash: ghost_hash,
        address: ghost_address,
    };

    let mut slots = Vec::with_capacity(auth_slots);
    for index in 0..body_auth_slots {
        let body_index = index + TX_DELTA;
        let tx_body_hash = tx_hashes[body_index].clone();
        let expected_address = spine_inputs[body_index].leaves[TX8X2_LEAF_INPUT_OWNER].clone();
        let live = live_bits[index].eval(b.values());
        assert!(live == F128::ZERO || live == F128::ONE);
        let kind = if live == F128::ONE {
            CanonicalSelectedZkAuthorizationSlotKind::Live
        } else {
            CanonicalSelectedZkAuthorizationSlotKind::Ghost
        };
        let native_statement = noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
            tx_body_hash: std::array::from_fn(|lane| block_from_alias(b, &tx_body_hash[lane])),
            address: std::array::from_fn(|lane| block_from_alias(b, &expected_address[lane])),
        };
        if kind == CanonicalSelectedZkAuthorizationSlotKind::Ghost {
            assert_eq!(native_statement, ghost_statement);
        }
        slots.push(CanonicalSelectedZkAuthorizationSlot {
            tx_body_hash: Some(tx_body_hash),
            expected_address: Some(expected_address),
            liveness: live_bits[index].clone(),
            native_statement,
            kind,
        });
    }
    if auth_slots > body_auth_slots {
        slots.push(CanonicalSelectedZkAuthorizationSlot {
            tx_body_hash: None,
            expected_address: None,
            liveness: live_bits[auth_slots - 1].clone(),
            native_statement: ghost_statement,
            kind: CanonicalSelectedZkAuthorizationSlotKind::Pad255,
        });
    }
    CanonicalSelectedZkAuthorizationCapability { slots }
}

#[cfg(test)]
pub(in crate::acceptance) fn canonical_selected_zk_authorization_fixture(
    live_count: usize,
) -> (FieldR1csBuilder, CanonicalSelectedZkAuthorizationCapability) {
    canonical_selected_zk_authorization_fixture_for_tier(255, live_count)
}

#[cfg(test)]
pub(in crate::acceptance) fn canonical_selected_zk_authorization_fixture_for_tier(
    tier: usize,
    live_count: usize,
) -> (FieldR1csBuilder, CanonicalSelectedZkAuthorizationCapability) {
    let geometry = crate::region_sidecar::selected_zk_block_geometry(tier)
        .expect("test fixture tier is canonical");
    let body_auth_slots = geometry.tier;
    assert!(live_count <= body_auth_slots);
    let mut b = FieldR1csBuilder::new();
    let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
    let ghost_spine = noid_gkr::spine_statement::spine_inputs_from_body(&ghost_body);
    let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
    let spine_inputs = (0..=body_auth_slots)
        .map(|_| SpineInputsTrace::alloc(&mut b, &ghost_spine))
        .collect::<Vec<_>>();
    let tx_hashes = (0..=body_auth_slots)
        .map(|_| ghost_hash.map(|value| alloc_block(&mut b, value)))
        .collect::<Vec<_>>();
    let live_bits = (0..geometry.auth_tiles)
        .map(|index| LinExpr::from_wire(b.alloc_bool(index < live_count)))
        .collect::<Vec<_>>();
    let before_mint = b.num_wires();
    let capability = mint_canonical_selected_zk_authorization_capability(
        &b,
        &tx_hashes,
        &spine_inputs,
        &live_bits,
    );
    assert_eq!(b.num_wires(), before_mint, "capability mint added rows");
    (b, capability)
}

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
    /// Selected production authenticates the transaction root in Meta-B; no
    /// directed path carrier survives in the Block statement.
    /// Per-authorization-slot liveness bits: real slots ONE, canonical ghost
    /// suffix ZERO, plus the permanently dead B255 authorization pad. Boolean
    /// and monotone; their integer sum pins USER_TX_COUNT.
    pub live_bits: Vec<LinExpr>,
    /// Bitmap-derived, slot-sorted unique live action prefix. Its physical
    /// permutation source is canonical body order.
    pub compacted_actions: CompactedActionTrace,
    pub exact_state: ExactStateSlotWires,
}

struct BlockSlotsCoreAssembly {
    slots: BlockSlots,
    selected_region: Option<SelectedZkBlockRegionBinding>,
}

/// Private selected-B255 handoff for the production outer Block owner.  It
/// keeps the ordinary Block statement aliases and the opaque bound V4 region
/// together until the owner has appended its public-IO pins and built the
/// same builder.
pub(in crate::acceptance) struct SelectedZkBlockSlotsAssembly {
    slots: BlockSlots,
    region: SelectedZkBlockRegionBinding,
}

impl SelectedZkBlockSlotsAssembly {
    pub(in crate::acceptance) fn slots(&self) -> &BlockSlots {
        &self.slots
    }

    #[cfg(feature = "selected-zk-measurement")]
    pub(in crate::acceptance) fn region_vk(&self) -> &BlockRegionSidecarVk {
        self.region.vk()
    }

    pub(in crate::acceptance) fn into_region_binding(self) -> SelectedZkBlockRegionBinding {
        self.region
    }
}

/// Canonical authorization entry. The proof bundle is owned and cannot be
/// omitted, replaced by a transparent proof, or selected by a runtime mode.
pub(in crate::acceptance) fn build_block_slots_selected_zk(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
    tier: usize,
    proofs: SelectedZkAuthorizationProofBundle,
) -> SelectedZkBlockSlotsAssembly {
    assert!(
        crate::region_sidecar::selected_zk_block_geometry(tier).is_some(),
        "selected backend tier is not canonical"
    );
    let mut assembly = build_selected_zk_block_slots_core(
        b,
        start_accumulator,
        end_accumulator,
        inputs,
        proof,
        tier,
        proofs,
    );
    let region = assembly
        .selected_region
        .take()
        .expect("selected backend returned its opaque bound region");
    SelectedZkBlockSlotsAssembly {
        slots: assembly.slots,
        region,
    }
}

fn build_selected_zk_block_slots_core(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
    tier: usize,
    authorization_proofs: SelectedZkAuthorizationProofBundle,
) -> BlockSlotsCoreAssembly {
    // validate_component_shape + the single-block batch shape, as asserts.
    let witness = &inputs.accepted_claim_witness;
    assert_eq!(witness.headers.len(), 1, "one block per link");
    assert_eq!(witness.accepted_block_claims.len(), 1);
    assert_eq!(inputs.accepted_claim_hash_inputs.len(), 1);
    assert_eq!(inputs.exact_state_structural_inputs.len(), 1);
    assert_eq!(proof.exact_state.len(), 1);
    assert_eq!(inputs.tx_body_inputs.len(), inputs.tx_body_hashes.len());
    // verify_authorization_components count check (structural side).
    assert_eq!(
        inputs.authorization_inputs.len(),
        inputs.authorization_totals.user_tx_count
    );
    assert_eq!(
        noid_chain::consensus::params::user_tx_class_tier(inputs.authorization_inputs.len()),
        Some(tier),
        "selected Block capacity must match its consensus class"
    );

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
            pin_eq(
                b,
                &claim.fields[claim_at + lane],
                &header.fields[field_at + lane],
            );
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
    pin_eq(
        b,
        &claim.fields[parent + hc::LOG_SLOTS],
        &start_acc.log_slots,
    );
    // Consensus-counter continuity: the START accumulator carries the
    // PARENT header's counters (the claim transcript's parent section) and
    // the END accumulator this header's child counters — the link chain
    // rule `start == prev.end` then closes the counter chain across
    // blocks (previously an unbound residue: the counters fed only the
    // claim hash with no accumulator wire to pin against).
    pin_eq(
        b,
        &claim.fields[parent + hc::ACTIVE_SLOT_COUNT],
        &start_acc.active_slot_count,
    );
    pin_eq(
        b,
        &claim.fields[parent + hc::ALLOC_COUNTER],
        &start_acc.alloc_counter,
    );
    pin_eq(
        b,
        &end_acc.active_slot_count,
        &header.fields[hf::ACTIVE_SLOT_COUNT],
    );
    pin_eq(b, &end_acc.alloc_counter, &header.fields[hf::ALLOC_COUNTER]);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: claim-hash killshot+[D]");
    // ---- Tx8x2 body-spine component. Region mode moves the whole final
    // 31-permutation-per-tx replay onto the shared walk A (compress tree +
    // TAG_TX8X2 wrap): only the statement wires are allocated here — the SAME
    // wire vectors the inline slot returns, so every downstream consumer
    // (tx-root leaves, owner-auth tx_body_hash pins, claim lanes) is
    // untouched — and the handoff carries them into the plural discharge.
    // The inline killshot proof is not consumed in-trace (nodes still verify
    // it natively; π proves the statement directly).
    // Tier capacity: the block carries capacity-many tx slots — the real
    // transactions followed by canonical GHOST-body slots (the protocol
    // ghost tx), so `tx_hashes`/`spine_inputs` are capacity-length and every
    // per-tx-slot structure below is class-fixed. `delta` = non-user txs
    // (the coinbase when present) — a class constant within a tier.
    let n_real_txs = inputs.tx_body_inputs.len();
    let tx_delta = n_real_txs
        .checked_sub(inputs.authorization_inputs.len())
        .expect("every user tx is a spine instance");
    assert_eq!(
        tx_delta, 1,
        "an accepted non-genesis block has exactly one mandatory coinbase"
    );
    let cap_txs = tier + tx_delta;
    assert!(
        !inputs.tx_body_inputs.is_empty(),
        "selected Block carries a body"
    );
    let mut spine_natives: Vec<SpineInputs> = inputs.tx_body_inputs.clone();
    let mut hash_natives: Vec<[Block128; 2]> = inputs.tx_body_hashes.clone();
    if cap_txs > n_real_txs {
        let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
        let ghost_spine = noid_gkr::spine_statement::spine_inputs_from_body(&ghost_body);
        let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
        for _ in n_real_txs..cap_txs {
            spine_natives.push(ghost_spine.clone());
            hash_natives.push(ghost_hash);
        }
    }
    let spine_inputs: Vec<SpineInputsTrace> = spine_natives
        .iter()
        .map(|input| SpineInputsTrace::alloc(b, input))
        .collect();
    let tx_hashes: Vec<[LinExpr; 2]> = hash_natives
        .iter()
        .map(|hash| std::array::from_fn(|lane| alloc_block(b, hash[lane])))
        .collect();
    let spine_region_data = Some(spine_region_data_from_wires(
        b,
        &spine_natives,
        &hash_natives,
        &spine_inputs,
        &tx_hashes,
    ));

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: spine (tiles+tree data)");
    // ---- Slot liveness (tier capacity): one witness bit per authorization
    // slot — 1 for the real txs, 0 for the ghost padding. Boolean and
    // MONOTONE (no live slot after a dead one), so the vector is determined
    // by its integer sum, which pins to the claim's USER_TX_COUNT lane
    // below. Every count that reaches a claim lane is gated by these bits,
    // replacing the content-shaped const pins with class-fixed structure.
    let n_real_user = inputs.authorization_inputs.len();
    let n_auth_slots = tier_auth_slot_count(Some(tier), n_real_user);
    let live_bits: Vec<LinExpr> = (0..n_auth_slots)
        .map(|i| {
            let v = Block128::from(if i < n_real_user { 1u128 } else { 0u128 });
            alloc_block(b, v)
        })
        .collect();
    for wire in &live_bits {
        let square = mul(b, wire, wire);
        pin_eq(b, &square, wire);
    }
    for index in 0..n_auth_slots.saturating_sub(1) {
        let not_previous = live_bits[index].add_const(F128::ONE);
        let dead_then_live = mul(b, &live_bits[index + 1], &not_previous);
        pin_zero(b, &dead_then_live);
    }
    let body_user_slots = tier;
    assert!(body_user_slots <= live_bits.len());
    for auth_pad in &live_bits[body_user_slots..] {
        // B255 has one power-of-two authorization PAD but only 255 body and
        // action slots. It can never impersonate transaction 256.
        pin_zero(b, auth_pad);
    }
    let body_live_bits = &live_bits[..body_user_slots];

    // Coinbase L0 = parent tip. In a capacity class every user slot gets the
    // same live/ghost gated relation; the non-capacity path pins all real L0s
    // directly.
    bind_tx_epoch_anchors(
        b,
        &start_acc,
        &spine_inputs,
        n_real_txs,
        tx_delta,
        Some(body_live_bits),
    );

    // Canonical body-order action candidates. Coinbase has exactly one live
    // mint; each user tier slot contributes its eight input and two output
    // bitmap positions. The extra B255 authorization PAD has no body/action
    // slot and is excluded below by the tx-hash/spine bound.
    let user_action_slots = tier.saturating_mul(noid_tx::TX_ACTIONS);
    let mut action_candidates = Vec::with_capacity(user_action_slots + tx_delta);
    let mut selected_input_bits = Vec::with_capacity(tier.saturating_mul(noid_tx::TX_INPUTS));
    let mut selected_output_bits =
        Vec::with_capacity(tier.saturating_mul(noid_tx::TX_OUTPUTS) + tx_delta);
    let coinbase = bind_coinbase_action_with_amount(b, &spine_inputs[0]);
    for lane in 0..2 {
        pin_eq(
            b,
            &coinbase.action.owner[lane],
            &header.fields[hf::MINER + lane],
        );
    }
    selected_output_bits.push(coinbase.action.live.clone());
    action_candidates.push(coinbase.action);
    let coinbase_amount = coinbase.amount;
    let coinbase_amount_bits: [Wire; 64] = coinbase.amount_bits;

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: liveness bits");
    // ---- tx_root component: paths for the REAL leaves, position-pinned.
    // Region mode moves the path hashing onto the shared walk B (one
    // TAG_COMPRESS leg): the entry/root closures ride the SAME statement
    // wires (spine tx hashes / underlying universal Merkle root M) via cell pins, and the
    // position + padding-rim bindings become const cell pins on the
    // committed direction/sibling cells — the exact constants pinned below
    // on the inline slot's statement wires.
    assert!(
        !inputs.tx_root_inputs.is_empty(),
        "selected Block carries the canonical transaction root"
    );
    let tx_root_region_data = Some(tx_root_region_capacity_handoff(
        b,
        &inputs.tx_root_inputs,
        &inputs.tx_body_hashes,
        &tx_hashes,
        body_live_bits,
        tx_delta,
    ));
    let merkle_root = tx_root_region_data
        .as_ref()
        .expect("selected Meta-B transaction-root handoff")
        .root_w
        .clone();
    let header_root = [
        header.fields[hf::TX_ROOT].clone(),
        header.fields[hf::TX_ROOT + 1].clone(),
    ];
    bind_tx_root_count_wrapper(
        b,
        &merkle_root,
        &claim.fields[claim_layout::TX_COUNT],
        &header_root,
    );

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: tx-root");
    // ---- exact_state component + its statement anchors. The production
    // relation consumes the authoritative sibling frontier and derives the
    // fixed-capacity paired local/upper schedule.
    let structural_es = &inputs.exact_state_structural_inputs[0];
    let (touched_capacity, segment_capacity) =
        exact_state_region_capacities(structural_es, Some(tier));
    let (exact_state, es_region_data) = build_exact_state_structural_region_slot(
        b,
        structural_es,
        touched_capacity,
        segment_capacity,
    )
    .expect("native-verified structural exact-state carrier");
    let es_region_data = Some(es_region_data);
    let parent_root = [
        claim.fields[parent + hc::STATE_ROOT].clone(),
        claim.fields[parent + hc::STATE_ROOT + 1].clone(),
    ];
    let child_root = [
        header.fields[hf::STATE_ROOT].clone(),
        header.fields[hf::STATE_ROOT + 1].clone(),
    ];
    let exact_state_depth = bind_exact_state_header_roots_dynamic(
        b,
        &exact_state.roots,
        &parent_root,
        &claim.fields[parent + hc::LOG_SLOTS],
        &child_root,
        &header.fields[hf::LOG_SLOTS],
    );

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: exact-state");
    // ---- Canonical ZK AuthGKR / Binary BaseFold authorization. Public
    // arithmetic is derived from the same body aliases and liveness wires that
    // mint the private, non-transferable all-tiles capability.
    use noid_tx::body_hash::TX8X2_LEAF_INPUT_OWNER;

    let geometry = crate::region_sidecar::selected_zk_block_geometry(tier)
        .expect("selected authorization tier is canonical");
    assert_eq!(body_user_slots, geometry.tier);
    assert_eq!(n_auth_slots, geometry.auth_tiles);
    assert_eq!(tx_delta, 1, "selected body aliases begin after coinbase");
    assert_eq!(
        spine_inputs.len(),
        body_user_slots + tx_delta,
        "selected authorization requires every canonical body spine"
    );

    let mut user_public_arithmetic = Vec::with_capacity(body_user_slots);
    for index in 0..body_user_slots {
        let body_index = index + tx_delta;
        let declared_live_inputs = selected_declared_live_input_count(b, &spine_inputs[body_index]);
        let expected_owner = spine_inputs[body_index].leaves[TX8X2_LEAF_INPUT_OWNER].clone();
        user_public_arithmetic.push(append_user_action_surface(
            b,
            &spine_inputs[body_index],
            &live_bits[index],
            &expected_owner,
            declared_live_inputs,
            &mut action_candidates,
            &mut selected_input_bits,
            &mut selected_output_bits,
        ));
    }
    let canonical_authorization = mint_canonical_selected_zk_authorization_capability(
        b,
        &tx_hashes,
        &spine_inputs,
        &live_bits,
    );
    assert_eq!(
        user_public_arithmetic.len(),
        body_user_slots,
        "one public-arithmetic trace per physical user body slot"
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: per-tx auth+public arithmetic");
    let _fee_arithmetic = bind_block_fee_arithmetic(
        b,
        &user_public_arithmetic,
        &start_acc.active_slot_count,
        &exact_state_depth.parent,
        &exact_state_depth.child,
        &coinbase_amount,
        &coinbase_amount_bits,
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: fee/burn/coinbase arithmetic");
    let selected_region = Some(bind_selected_zk_block_region(
        b,
        canonical_authorization,
        authorization_proofs,
        es_region_data
            .as_ref()
            .expect("selected exact-state region data"),
        tx_root_region_data
            .as_ref()
            .expect("selected tx-root region data"),
        spine_region_data
            .as_ref()
            .expect("selected spine region data"),
    ));
    crate::acceptance::row_ledger_mark(
        b,
        &mut ledger,
        "slots: selected auth+Meta/all-tiles assembly",
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: wallet plural/sidecar assembly");
    // Totals: transaction and action counts now come from the same liveness
    // and bitmap wires that feed compaction. All sums are INTEGERS
    // (ripple-carry over tower bits), not GF(2^128) XOR.
    // Tier capacity: count lanes bind to the same liveness sum that gates the
    // selected proof tiles. TX_COUNT includes the mandatory coinbase.
    let user_sum = pin_u64_sum(b, body_live_bits);
    pin_eq(b, &claim.fields[claim_layout::USER_TX_COUNT], &user_sum);
    if tx_delta == 1 {
        pin_u64_successor(b, &user_sum, &claim.fields[claim_layout::TX_COUNT]);
    } else {
        pin_eq(b, &claim.fields[claim_layout::TX_COUNT], &user_sum);
    }
    let live_input_sum = pin_u64_sum(b, &selected_input_bits);
    let output_sum = pin_u64_sum(b, &selected_output_bits);
    pin_eq(
        b,
        &claim.fields[claim_layout::LIVE_INPUT_COUNT],
        &live_input_sum,
    );
    pin_eq(b, &claim.fields[claim_layout::OUTPUT_COUNT], &output_sum);

    // Exact active-slot counter equation as unsigned integers:
    // parent + all mints (including coinbase) = child + all spends.
    // Both additions reject u64 overflow instead of silently wrapping in the
    // characteristic-two field.
    bind_active_slot_counter_delta(
        b,
        &start_acc.active_slot_count,
        &header.fields[hf::ACTIVE_SLOT_COUNT],
        &live_input_sum,
        &output_sum,
    );

    let class = super::shape::ShapeClass { tier };
    assert_eq!(
        action_candidates.len(),
        class.action_candidate_capacity(),
        "one coinbase action plus ten candidates per tier user slot"
    );
    let count_bits = range_check_bits(b, &live_input_sum, 12);
    let cap_plus_one = const_block(Block128::from((class.spend_capacity() + 1) as u128));
    let cap_bits = range_check_bits(b, &cap_plus_one, 12);
    pin_lt_strict(b, &count_bits, &cap_bits);
    let action_live_capacity = class.touched_capacity();
    bind_mint_packed_values_body_order(
        b,
        &mut action_candidates,
        &start_acc.alloc_counter,
        &header.fields[hf::ALLOC_COUNTER],
    );
    let compacted_actions = compact_action_rows(b, &action_candidates, action_live_capacity);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: action allocator+route+order");

    let paired_cells = selected_region
        .as_ref()
        .map(SelectedZkBlockRegionBinding::paired)
        .expect("selected region carries paired exact-state cells");
    bind_paired_exact_state_transition(
        b,
        &compacted_actions,
        &exact_state,
        paired_cells,
        &exact_state_depth.child,
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: exact-state action+paired topology");

    bind_structural_frontier_count_from_actions_dynamic(
        b,
        &compacted_actions.rows,
        &compacted_actions.slot_bits,
        &compacted_actions.adjacent_msb_one_hot,
        &exact_state_depth.child,
        &claim.fields[claim_layout::STATE_FRONTIER_NODE_COUNT],
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: structural frontier count");
    // ---- Direct ten-lane accumulator transition. The child header is the
    // sole transition statement; there is no rolling claim/hash fold.
    let child = DirectChildWires {
        block_id: header.expected_block_id.clone(),
        prev_block_hash: [
            header.fields[hf::PREV_BLOCK_HASH].clone(),
            header.fields[hf::PREV_BLOCK_HASH + 1].clone(),
        ],
        state_root: [
            header.fields[hf::STATE_ROOT].clone(),
            header.fields[hf::STATE_ROOT + 1].clone(),
        ],
        height: header.fields[hf::HEIGHT].clone(),
        log_slots: header.fields[hf::LOG_SLOTS].clone(),
        active_slot_count: header.fields[hf::ACTIVE_SLOT_COUNT].clone(),
        alloc_counter: header.fields[hf::ALLOC_COUNTER].clone(),
    };
    build_direct_accumulator_transition_slot(b, &start_acc, &child, &end_acc);

    // ---- Header-hash checkpoint component over the SAME wires. The former
    // chain-accumulator killshot leg is gone: continuity is the direct
    // arithmetic relation above.
    build_checkpoint_poseidon_slot_with_inputs(
        b,
        &proof.checkpoint_poseidon,
        std::slice::from_ref(&header),
        1,
    );

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: direct accumulator + header hash");

    let slots = BlockSlots {
        header,
        claim,
        start_acc,
        end_acc,
        spine_inputs,
        tx_hashes,
        live_bits,
        compacted_actions,
        exact_state,
    };
    BlockSlotsCoreAssembly {
        slots,
        selected_region,
    }
}

#[cfg(test)]
mod tx_epoch_anchor_tests {
    use super::*;
    use noid_core::TowerField;

    fn active_counter_case(
        parent: u128,
        child: u128,
        spends: u128,
        mints: u128,
    ) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>) {
        let mut b = FieldR1csBuilder::new();
        let parent = alloc_block(&mut b, Block128::from(parent));
        let child = alloc_block(&mut b, Block128::from(child));
        let spends = alloc_block(&mut b, Block128::from(spends));
        let mints = alloc_block(&mut b, Block128::from(mints));
        bind_active_slot_counter_delta(&mut b, &parent, &child, &spends, &mints);
        b.build()
    }

    #[test]
    fn active_counter_uses_exact_spend_mint_delta() {
        for (parent, child, spends, mints) in [(7, 8, 2, 3), (7, 5, 3, 1), (0, 1, 0, 1)] {
            let (r1cs, witness) = active_counter_case(parent, child, spends, mints);
            assert!(r1cs.satisfies(&witness));
        }
    }

    #[test]
    fn active_counter_rejects_wrong_delta_and_overflow() {
        for case in [(7, 9, 2, 3), (u64::MAX as u128, 0, 0, 1)] {
            let (r1cs, witness) = active_counter_case(case.0, case.1, case.2, case.3);
            assert!(!r1cs.satisfies(&witness));
        }
    }

    fn start_accumulator() -> ChainAccumulator {
        ChainAccumulator {
            height: 143,
            tip_block_id: [0x11; 32],
            state_root: [0x22; 32],
            log_slots: 24,
            active_slot_count: 7,
            alloc_counter: 9,
            epoch_anchor_id: [0x33; 32],
        }
    }

    fn bodies(start: &ChainAccumulator) -> Vec<SpineInputs> {
        let mut coinbase = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        coinbase.leaves[noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR] =
            digest_lanes(&start.tip_block_id);
        let mut user = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        user.leaves[noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR] =
            digest_lanes(&start.epoch_anchor_id);
        let ghost =
            noid_gkr::spine_statement::spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
        vec![coinbase, user, ghost]
    }

    fn build_relation(
        start: &ChainAccumulator,
        bodies: &[SpineInputs],
        real_users: usize,
    ) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>) {
        assert_eq!(bodies.len(), 3, "test tier has coinbase + two user slots");
        assert!(real_users <= 2);
        let mut b = FieldR1csBuilder::new();
        let start = AccumulatorWires::alloc(&mut b, start);
        let traces: Vec<_> = bodies
            .iter()
            .map(|body| SpineInputsTrace::alloc(&mut b, body))
            .collect();
        let live_bits: Vec<_> = (0..2)
            .map(|i| alloc_block(&mut b, Block128::from(u128::from(i < real_users))))
            .collect();
        for live in &live_bits {
            let square = mul(&mut b, live, live);
            pin_eq(&mut b, &square, live);
        }
        bind_tx_epoch_anchors(&mut b, &start, &traces, 1 + real_users, 1, Some(&live_bits));
        b.build()
    }

    fn satisfies(start: &ChainAccumulator, bodies: &[SpineInputs], real_users: usize) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (r1cs, witness) = build_relation(start, bodies, real_users);
            r1cs.satisfies(&witness)
        }))
        .unwrap_or(false)
    }

    #[test]
    fn coinbase_user_and_ghost_anchor_recombination() {
        let start = start_accumulator();
        let honest = bodies(&start);
        assert!(satisfies(&start, &honest, 1));

        for (body, leaf, lane) in [
            (0usize, noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR, 0usize),
            (1, noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR, 1),
            (2, noid_tx::body_hash::TX8X2_LEAF_FEE, 0),
            (2, noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR, 1),
        ] {
            let mut bad = honest.clone();
            bad[body].leaves[leaf][lane] += Block128::ONE;
            assert!(
                !satisfies(&start, &bad, 1),
                "body {body} leaf {leaf} lane {lane} recombination accepted"
            );
        }
    }

    #[test]
    fn capacity_matrix_is_identical_across_real_user_counts() {
        let start = start_accumulator();
        let one_user = bodies(&start);
        let mut two_users = one_user.clone();
        two_users[2] = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        two_users[2].leaves[noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR] =
            digest_lanes(&start.epoch_anchor_id);

        let (one_r1cs, one_witness) = build_relation(&start, &one_user, 1);
        let (two_r1cs, two_witness) = build_relation(&start, &two_users, 2);
        assert!(one_r1cs.satisfies(&one_witness));
        assert!(two_r1cs.satisfies(&two_witness));
        assert_eq!(one_r1cs.statement_digest(), two_r1cs.statement_digest());
        assert_eq!(one_r1cs.useful_rows, two_r1cs.useful_rows);
    }

    #[test]
    fn b255_body_liveness_excludes_the_256th_authorization_pad() {
        let start = start_accumulator();
        let mut natives = bodies(&start);
        let ghost = natives.pop().expect("small fixture ghost");
        while natives.len() < 1 + noid_chain::consensus::params::BLOCK_MAX_USER_TXS {
            natives.push(ghost.clone());
        }
        let mut b = FieldR1csBuilder::new();
        let start_w = AccumulatorWires::alloc(&mut b, &start);
        let traces: Vec<_> = natives
            .iter()
            .map(|body| SpineInputsTrace::alloc(&mut b, body))
            .collect();
        let auth_capacity =
            super::tier_auth_slot_count(Some(noid_chain::consensus::params::BLOCK_MAX_USER_TXS), 1);
        assert_eq!(auth_capacity, 256);
        let live_bits: Vec<_> = (0..auth_capacity)
            .map(|i| alloc_block(&mut b, Block128::from(u128::from(i == 0))))
            .collect();
        for live in &live_bits {
            let square = mul(&mut b, live, live);
            pin_eq(&mut b, &square, live);
        }
        pin_zero(&mut b, &live_bits[255]);
        bind_tx_epoch_anchors(&mut b, &start_w, &traces, 2, 1, Some(&live_bits[..255]));
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }
}

#[cfg(test)]
mod paired_exact_state_connection_tests {
    use super::*;
    use crate::acceptance::trace::exact_state::{ExactStateRootWires, SlotLeafInputsTrace};
    use crate::acceptance::trace::region_source_binding::{
        PairedLocalExactStateCells, PairedUpperExactStateCells,
    };
    use noid_ivc_core::field_r1cs::FieldR1cs;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        None,
        LocalEntry,
        LocalDirection,
        LocalChain,
        UpperEntry,
        UpperDirection,
        UpperEndpoint,
    }

    fn pair(b: &mut FieldR1csBuilder, values: [u128; 2]) -> [LinExpr; 2] {
        std::array::from_fn(|lane| alloc_block(b, Block128::from(values[lane])))
    }

    fn directions(b: &mut FieldR1csBuilder, bits: u16) -> [LinExpr; 16] {
        std::array::from_fn(|bit| alloc_block(b, Block128::from(u128::from((bits >> bit) & 1))))
    }

    fn spend_action(
        b: &mut FieldR1csBuilder,
        slot: u32,
        value: u128,
        owner: [u128; 2],
    ) -> ActionRowTrace {
        ActionRowTrace {
            live: LinExpr::from_wire(b.alloc_bool(true)),
            slot_index: alloc_block(b, Block128::from(slot as u128)),
            value: alloc_block(b, Block128::from(value)),
            owner: pair(b, owner),
            is_mint: LinExpr::zero(),
        }
    }

    fn leaf(
        b: &mut FieldR1csBuilder,
        value: u128,
        owner: [u128; 2],
        expected: [u128; 2],
    ) -> SlotLeafInputsTrace {
        SlotLeafInputsTrace {
            packed_value: alloc_block(b, Block128::from(value)),
            owner_hi: alloc_block(b, Block128::from(owner[0])),
            owner_lo: alloc_block(b, Block128::from(owner[1])),
            expected_leaf: pair(b, expected),
        }
    }

    fn drive_relation(b: &mut FieldR1csBuilder, fault: Fault) {
        // Both live slots belong to segment zero.  Using the real action
        // compactor gives this isolated connection test constrained slot bits
        // and adjacent-MSB metadata instead of trusting hand-written hints.
        let source = [
            spend_action(b, 5, 71, [81, 82]),
            spend_action(b, 9, 73, [83, 84]),
        ];
        let actions = compact_action_rows(b, &source, source.len());

        // The leaf hash outputs are deliberately arbitrary: this test targets
        // only the connection layer, while the region independently proves
        // the hash walks.  The semantic preimages still satisfy the two spend
        // transitions (old body value/owner, new canonical empty slot).
        let old_leaves = [
            leaf(b, 71, [81, 82], [11, 12]),
            leaf(b, 73, [83, 84], [13, 14]),
        ];
        let new_leaves = [leaf(b, 0, [0, 0], [21, 22]), leaf(b, 0, [0, 0], [23, 24])];
        let roots = ExactStateRootWires {
            old_root: pair(b, [901, 902]),
            new_root: pair(b, [951, 952]),
            active_depth: 24,
        };
        let exact_state = ExactStateSlotWires {
            slot_leaves: old_leaves.into_iter().chain(new_leaves).collect(),
            roots,
        };

        let mut first_old_entry = [11, 12];
        if fault == Fault::LocalEntry {
            first_old_entry[0] += 1;
        }
        let mut first_directions = 5u16;
        if fault == Fault::LocalDirection {
            first_directions ^= 1;
        }
        let mut first_after = [201, 202];
        if fault == Fault::LocalChain {
            first_after[0] += 1;
        }
        let local = vec![
            PairedLocalExactStateCells {
                old_entry: pair(b, first_old_entry),
                new_entry: pair(b, [21, 22]),
                old_root: pair(b, [101, 102]),
                new_root: pair(b, first_after),
                directions: directions(b, first_directions),
            },
            PairedLocalExactStateCells {
                old_entry: pair(b, [13, 14]),
                new_entry: pair(b, [23, 24]),
                old_root: pair(b, [201, 202]),
                new_root: pair(b, [301, 302]),
                directions: directions(b, 9),
            },
        ];

        let mut upper_old_entry = [101, 102];
        if fault == Fault::UpperEntry {
            upper_old_entry[0] += 1;
        }
        let upper_directions = if fault == Fault::UpperDirection { 1 } else { 0 };
        let old_roots = std::array::from_fn(|level| {
            if level == 7 {
                pair(b, [901, 902])
            } else {
                pair(b, [1_000 + 2 * level as u128, 1_001 + 2 * level as u128])
            }
        });
        let new_roots = std::array::from_fn(|level| {
            if level == 7 {
                let mut endpoint = [951, 952];
                if fault == Fault::UpperEndpoint {
                    endpoint[0] += 1;
                }
                pair(b, endpoint)
            } else {
                pair(b, [2_000 + 2 * level as u128, 2_001 + 2 * level as u128])
            }
        });
        let paired = PairedExactStateCells {
            local,
            upper: vec![PairedUpperExactStateCells {
                old_entry: pair(b, upper_old_entry),
                new_entry: pair(b, [301, 302]),
                old_roots,
                new_roots,
                directions: directions(b, upper_directions),
            }],
        };

        let depth_value = alloc_block(b, Block128::from(24u128));
        let child_depth = StateDepthTrace::bind(b, &depth_value);
        bind_paired_exact_state_transition(b, &actions, &exact_state, &paired, &child_depth);
    }

    fn full_case(fault: Fault) -> (FieldR1cs, Vec<F128>) {
        let mut b = FieldR1csBuilder::new();
        drive_relation(&mut b, fault);
        b.build()
    }

    fn witness_case(fault: Fault) -> (usize, Vec<F128>) {
        let mut b = FieldR1csBuilder::new_witness_only();
        drive_relation(&mut b, fault);
        b.build_witness_only()
    }

    #[test]
    fn paired_exact_state_connection_layer_rejects_every_broken_cross_link() {
        let (r1cs, honest_full) = full_case(Fault::None);
        assert!(r1cs.satisfies(&honest_full), "honest connection fixture");

        let (honest_wires, honest_witness) = witness_case(Fault::None);
        assert_eq!(honest_wires, r1cs.useful_rows, "honest wire-count parity");
        assert_eq!(honest_witness, honest_full, "honest witness-only parity");
        assert!(r1cs.satisfies(&honest_witness));

        for fault in [
            Fault::LocalEntry,
            Fault::LocalDirection,
            Fault::LocalChain,
            Fault::UpperEntry,
            Fault::UpperDirection,
            Fault::UpperEndpoint,
        ] {
            let (wire_count, witness) = witness_case(fault);
            assert_eq!(
                wire_count, r1cs.useful_rows,
                "{fault:?} changed the matrix wire count"
            );
            assert_eq!(
                witness.len(),
                honest_full.len(),
                "{fault:?} changed the padded witness length"
            );
            assert!(
                !r1cs.satisfies(&witness),
                "{fault:?} cross-link mutation was accepted"
            );
        }
    }
}
