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
//! - the direct eleven-lane accumulator transition shares the header block-id,
//!   parent-tip, state/depth/counter and height wires; transaction epoch is
//!   selected by a constrained `height mod 144` relation;
//! - every tx-root Merkle path pins its root to the underlying universal
//!   256-leaf Merkle root `M`, its leaf to coinbase or a complete PagedSpend
//!   logical hash, its
//!   direction bits to the
//!   CONSTANT bits of its tx position, and the last real path pins its
//!   right-hand siblings to the canonical zero-subtree digests (the padding
//!   rim the native root reconstruction binds); a domain-separated
//!   `TAG_TXROOT(M, tx_count)` wrapper then pins to the header `tx_root`;
//! - each owner-auth slot pins `(logical_txid, owner)` to the constrained
//!   START..END group and discharges its wallet-PCS obligation;
//! - production exact state derives a fixed-capacity paired local/upper walk
//!   from the sibling-only structural carrier. Slot-sorted action leaves and
//!   all 32 slot bits bind its entries/directions; local and segment chains
//!   end at the parent/grown-parent and child header roots selected by the
//!   header-bound dynamic depth.
//! - page-selected amounts accumulate into one checked group conservation
//!   equation; those same group counts drive minimum fee and deterministic
//!   burn, and the mandatory coinbase is bounded by child-depth reward plus
//!   the checked 72-bit claimable-fee aggregate.
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
use noid_poseidon2b::native::domain::{capacity_iv, TAG_BLOCKHDR, TAG_SEMHDR, TAG_TXROOT};

use super::trace::accepted_claim_batch::{
    build_direct_accumulator_transition_slot, compress_with_tag_trace, digest_lanes,
    AccumulatorWires, DirectChildWires,
};
use super::trace::action_compaction::{
    bind_mint_packed_values_body_order, compact_action_rows, CompactedActionTrace,
};
use super::trace::action_surface::{
    bind_coinbase_action_with_amount, bind_user_action_surface, ActionRowTrace, ActionSurfaceTrace,
};
use super::trace::exact_state::{
    bind_actions_to_exact_state_leaves, bind_exact_state_header_roots_dynamic,
    build_exact_state_structural_region_slot, select_upper_paired_roots, ExactStateSlotWires,
    PairedRootCellPair, StateDepthTrace,
};
use super::trace::fee_arithmetic::bind_block_fee_arithmetic;
use super::trace::paged_spend::{bind_paged_spend_stream, PagedSpendGroupTrace};
use super::trace::public_arithmetic::{bind_user_public_arithmetic, UserPublicArithmeticTrace};
use super::trace::region_source_binding::{
    PairedExactStateCells, SpineInstanceRegion, SpineRegionData, TxRootPathRegion, TxRootRegionData,
};
use super::trace::segment_compaction::{bind_segment_upper_chain, compact_segment_updates};
use super::trace::tx_body_spine::SpineInputsTrace;
use super::trace::zk_authorization_candidate::{
    bind_selected_zk_block_region, PreparedSelectedZkAuthorizations, SelectedZkBlockRegionBinding,
};
use super::trace::{
    alloc_block, const_block, flat_const, flat_of, integer_add_no_overflow, mul, pin_eq,
    pin_lt_strict, pin_zero, poseidon2b_permute, range_check_bits, FieldR1csBuilder, LinExpr, Wire,
    F128,
};
use crate::acceptance::history_step::HistoryStepBlockComponents;
use crate::accumulator::ChainAccumulator;
use crate::region_sidecar::{BlockRegionPreparation, BlockRegionSidecarVk, RegionSidecarError};
use noid_chain::block_header::BlockHeader;
use noid_gkr::SpineInputs;
use noid_ivc_core::deep_chain::spine::SpineInstanceFlat;
use noid_ivc_core::field_circuit::f128_to_u128;

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

/// Offsets inside the 15-field semantic header schedule — the PoW schedule
/// (`pow_header_fields_into` order) with the nonce removed. The relation is
/// nonce-free: the chain link over the exact nonce stays native, and the
/// child step's parent-seal replay derives the parent block id in-circuit.
pub mod header_fields {
    pub const PREV_BLOCK_HASH: usize = 0; // 2 lanes
    pub const STATE_ROOT: usize = 2; // 2
    pub const TX_ROOT: usize = 4; // 2
    pub const TIMESTAMP: usize = 6;
    pub const HEIGHT: usize = 7;
    pub const MINER: usize = 8; // 2
    pub const TARGET: usize = 10; // 2
    pub const LOG_SLOTS: usize = 12;
    pub const ACTIVE_SLOT_COUNT: usize = 13;
    pub const ALLOC_COUNTER: usize = 14;
    pub const FIELDS: usize = 15;
}

const _: () =
    assert!(header_fields::FIELDS + 1 == noid_chain::consensus::pow::POW_HEADER_FIELD_COUNT);

/// Class-independent nonce-free suffix: direct accumulator transition plus
/// the exact semantic `SEMHDR` replay. Every row is known at template time.
const DIRECT_BLOCK_TAIL_ROWS: usize = 4_042;

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

fn append_page_action_surface(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    page_live: &LinExpr,
    candidates: &mut Vec<ActionRowTrace>,
    input_selectors: &mut Vec<LinExpr>,
    output_selectors: &mut Vec<LinExpr>,
) -> (ActionSurfaceTrace, UserPublicArithmeticTrace) {
    let surface = bind_user_action_surface(b, spine, page_live);
    let arithmetic = bind_user_public_arithmetic(b, spine, &surface);
    input_selectors.extend(surface.selected_inputs.iter().cloned());
    output_selectors.extend(surface.selected_outputs.iter().cloned());
    candidates.extend(surface.ordered_rows());
    (surface, arithmetic)
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
#[cfg(test)]
fn tier_auth_slot_count(tier_user_tx_capacity: Option<usize>, n_real_user: usize) -> usize {
    tier_user_tx_capacity.map_or(n_real_user, |tier| {
        super::shape::ShapeClass { tier }.authorization_capacity()
    })
}

/// Exact-state class capacities used by both the real region build and its
/// native claim mirror. Tier builds are content-invariant. Transitional
/// non-tier region tests use their exact touched/segment counts.
fn exact_state_region_capacities(
    structural: &super::history_step::ExactStateStructuralFrontierInputs,
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
    parent_block_id: &[LinExpr; 2],
    user_anchor: &[LinExpr; 2],
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
            pin_eq(b, &spine_inputs[0].leaves[L0][lane], &parent_block_id[lane]);
        }
    }
    match capacity_live_bits {
        None => {
            assert_eq!(n_real_txs, spine_inputs.len());
            for spine in &spine_inputs[tx_delta..] {
                for lane in 0..2 {
                    pin_eq(b, &spine.leaves[L0][lane], &user_anchor[lane]);
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
                    let epoch_diff = spine.leaves[L0][lane].add(&user_anchor[lane]);
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
    groups: &[PagedSpendGroupTrace],
) -> CanonicalSelectedZkAuthorizationCapability {
    let auth_slots = groups.len();
    let geometry = crate::region_sidecar::selected_zk_block_geometry_for_auth_tiles(auth_slots)
        .expect("selected authorization capacity is canonical");
    let body_auth_slots = geometry.tier;
    assert_eq!(body_auth_slots, geometry.tier);
    assert_eq!(auth_slots, geometry.auth_tiles);
    if auth_slots > body_auth_slots {
        assert_eq!(geometry.tier, 255, "only B255 has an authorization PAD");
        assert_eq!(groups[auth_slots - 1].live.eval(b.values()), F128::ZERO);
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
        let group = &groups[index];
        let live = group.live.eval(b.values());
        assert!(live == F128::ZERO || live == F128::ONE);
        let kind = if live == F128::ONE {
            CanonicalSelectedZkAuthorizationSlotKind::Live
        } else {
            CanonicalSelectedZkAuthorizationSlotKind::Ghost
        };
        let dead = group.live.add_const(F128::ONE);
        let tx_body_hash = std::array::from_fn(|lane| {
            group.logical_txid[lane].add(&dead.scale(flat_of(ghost_hash[lane])))
        });
        let expected_address = std::array::from_fn(|lane| {
            group.input_owner[lane].add(&dead.scale(flat_of(ghost_address[lane])))
        });
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
            liveness: group.live.clone(),
            native_statement,
            kind,
        });
    }
    if auth_slots > body_auth_slots {
        slots.push(CanonicalSelectedZkAuthorizationSlot {
            tx_body_hash: None,
            expected_address: None,
            liveness: groups[auth_slots - 1].live.clone(),
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
    let ghost_hash = noid_gkr::ghost_tx::ghost_tx_body_hash();
    let ghost_address = ghost_body.input_owner.as_fields();
    let mut groups = (0..body_auth_slots)
        .map(|index| {
            let live = LinExpr::from_wire(b.alloc_bool(index < live_count));
            PagedSpendGroupTrace {
                live: live.clone(),
                logical_txid: ghost_hash.map(|value| {
                    alloc_block(
                        &mut b,
                        if index < live_count {
                            value
                        } else {
                            Block128::from(0u128)
                        },
                    )
                }),
                input_owner: ghost_address.map(|value| {
                    alloc_block(
                        &mut b,
                        if index < live_count {
                            value
                        } else {
                            Block128::from(0u128)
                        },
                    )
                }),
                fee: LinExpr::zero(),
                live_input_count: LinExpr::zero(),
                live_output_count: LinExpr::zero(),
                end_page: LinExpr::zero(),
            }
        })
        .collect::<Vec<_>>();
    if geometry.auth_tiles > body_auth_slots {
        groups.push(PagedSpendGroupTrace {
            live: LinExpr::zero(),
            logical_txid: [LinExpr::zero(), LinExpr::zero()],
            input_owner: [LinExpr::zero(), LinExpr::zero()],
            fee: LinExpr::zero(),
            live_input_count: LinExpr::zero(),
            live_output_count: LinExpr::zero(),
            end_page: LinExpr::zero(),
        });
    }
    let before_mint = b.num_wires();
    let capability = mint_canonical_selected_zk_authorization_capability(&b, &groups);
    assert_eq!(b.num_wires(), before_mint, "capability mint added rows");
    (b, capability)
}

/// Exact semantic header schedule used by the direct block relation.
///
/// The native PoW/ASERT/MTP path remains consensus authority. `HistoryStep`
/// recomputes the nonce-free `SEMHDR` projection so the recursive terminal
/// binds the complete semantic template; the chain-link id over the exact
/// nonce is checked natively at the tip and sealed in-circuit by the child
/// step's parent-seal replay.
pub struct DirectHeaderTrace {
    pub fields: Vec<LinExpr>,
    pub expected_semantic_id: [LinExpr; 2],
}

impl DirectHeaderTrace {
    fn alloc(b: &mut FieldR1csBuilder, header: &BlockHeader) -> Self {
        let fields = noid_chain::consensus::pow::pow_header_fields(header)
            .into_iter()
            .enumerate()
            .filter(|(index, _)| *index != noid_chain::consensus::pow::POW_NONCE_FIELD_INDEX)
            .map(|(_, field)| alloc_block(b, field))
            .collect();
        let semantic_id = digest_lanes(&noid_chain::block_header::semantic_header_id(header));
        Self {
            fields,
            expected_semantic_id: semantic_id.map(|lane| alloc_block(b, lane)),
        }
    }
}

/// Trace twin of the byte sponge over whole field lanes under `tag`. Mirrors
/// `Poseidon2bSponge`: pairs are rate blocks; an odd trailing lane shares its
/// final permutation with the `fill_padding` bytes (0x80 first, 0x01 last of
/// the remaining half-buffer); an even schedule pads one whole rate block.
fn sponge_lanes_trace(
    b: &mut FieldR1csBuilder,
    tag: noid_poseidon2b::native::domain::DomainTag,
    fields: &[LinExpr],
) -> [LinExpr; 2] {
    let [iv0, iv1] = capacity_iv(tag);
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        LinExpr::constant(flat_of(iv0)),
        LinExpr::constant(flat_of(iv1)),
    ];
    for pair in fields.chunks_exact(2) {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = poseidon2b_permute(b, state);
    }
    if fields.len() % 2 == 1 {
        let mut pad = [0u8; 16];
        pad[0] = 0x80;
        pad[15] |= 0x01;
        state[0] = state[0].add(&fields[fields.len() - 1]);
        state[1] = state[1].add_const(flat_of(Block128::from(u128::from_le_bytes(pad))));
    } else {
        let mut pad = [0u8; 32];
        pad[0] = 0x80;
        pad[31] |= 0x01;
        state[0] = state[0].add_const(flat_of(Block128::from(u128::from_le_bytes(
            pad[..16].try_into().expect("fixed pad lane"),
        ))));
        state[1] = state[1].add_const(flat_of(Block128::from(u128::from_le_bytes(
            pad[16..].try_into().expect("fixed pad lane"),
        ))));
    }
    state = poseidon2b_permute(b, state);
    [state[0].clone(), state[1].clone()]
}

fn bind_direct_semantic_id(b: &mut FieldR1csBuilder, header: &DirectHeaderTrace) {
    debug_assert_eq!(header.fields.len(), header_fields::FIELDS);
    let lanes = sponge_lanes_trace(b, TAG_SEMHDR, &header.fields);
    pin_eq(b, &lanes[0], &header.expected_semantic_id[0]);
    pin_eq(b, &lanes[1], &header.expected_semantic_id[1]);
}

/// Parent-seal witness: the exact parent header replayed under both header
/// domains. The chain-link id (`BLOCKHDR`, nonce included) glues the child's
/// `prev_block_hash` and the shifted epoch-anchor write; the nonce-free
/// projection (`SEMHDR`) glues the verified parent terminal tip. Fixed
/// geometry — independent of every tier.
pub(in crate::acceptance) struct ParentSealTrace {
    pub block_id: [LinExpr; 2],
    pub semantic_id: [LinExpr; 2],
    pub height: LinExpr,
}

impl ParentSealTrace {
    pub(in crate::acceptance) fn alloc(b: &mut FieldR1csBuilder, parent: &BlockHeader) -> Self {
        let fields: Vec<LinExpr> = noid_chain::consensus::pow::pow_header_fields(parent)
            .into_iter()
            .map(|field| alloc_block(b, field))
            .collect();
        let block_id = sponge_lanes_trace(b, TAG_BLOCKHDR, &fields);
        let semantic: Vec<LinExpr> = fields
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != noid_chain::consensus::pow::POW_NONCE_FIELD_INDEX)
            .map(|(_, wire)| wire.clone())
            .collect();
        let semantic_id = sponge_lanes_trace(b, TAG_SEMHDR, &semantic);
        let height = fields[header_fields::HEIGHT].clone();
        Self {
            block_id,
            semantic_id,
            height,
        }
    }
}

/// The primary statement wires of one assembled block, returned for the
/// HistoryStep-level accumulator bindings.
pub struct BlockSlots {
    /// The sealed semantic header wire set every other slot is pinned against.
    pub header: DirectHeaderTrace,
    pub start_acc: AccumulatorWires,
    pub end_acc: AccumulatorWires,
    pub spine_inputs: Vec<SpineInputsTrace>,
    pub tx_hashes: Vec<[LinExpr; 2]>,
    /// Physical page prefix driving body/action/exact-state geometry.
    pub page_live_bits: Vec<LinExpr>,
    /// Compacted logical-group prefix driving capsule and tx-root geometry.
    pub authorization_live_bits: Vec<LinExpr>,
    /// Bitmap-derived, slot-sorted unique live action prefix. Its physical
    /// permutation source is canonical body order.
    pub compacted_actions: CompactedActionTrace,
    pub exact_state: ExactStateSlotWires,
}

struct BlockSlotsCoreAssembly {
    slots: BlockSlots,
    selected_region: Option<SelectedZkBlockRegionBinding>,
    nonce_seal: DirectBlockNonceSeal,
}

/// Private selected-B255 handoff for the production outer Block owner.  It
/// keeps the ordinary Block statement aliases and the opaque bound V4 region
/// together until the owner has appended its public-IO pins and built the
/// same builder.
pub(in crate::acceptance) struct SelectedZkBlockSlotsAssembly {
    slots: BlockSlots,
    region: SelectedZkBlockRegionBinding,
    nonce_seal: Option<DirectBlockNonceSeal>,
    parent_block_id: [LinExpr; 2],
}

struct DirectBlockNonceSeal {
    template_header: BlockHeader,
    start_accumulator: ChainAccumulator,
    parent_header: BlockHeader,
}

impl DirectBlockNonceSeal {
    /// The relation is nonce-free: sealing only validates that the winning
    /// header is the exact template (any nonce) and that the end boundary is
    /// its exact parent-glued advance. No witness cell changes.
    fn seal(
        self,
        sealed_header: &BlockHeader,
        end_accumulator: &ChainAccumulator,
    ) -> Result<(), DirectBlockSealError> {
        let mut expected_header = self.template_header;
        expected_header.nonce = sealed_header.nonce;
        if expected_header != *sealed_header {
            return Err(DirectBlockSealError::HeaderChanged);
        }
        let expected_end = self
            .start_accumulator
            .advance(&self.parent_header, sealed_header)
            .map_err(|_| DirectBlockSealError::EndAccumulator)?;
        if expected_end != *end_accumulator {
            return Err(DirectBlockSealError::EndAccumulator);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::acceptance) enum DirectBlockSealError {
    AlreadySealed,
    HeaderChanged,
    EndAccumulator,
}

/// Unforgeable authority proving the owning HistoryStep builder has finished
/// before its direct region is finalized.
pub(crate) struct SelectedBlockAssemblyFinalizationSeal(());

impl SelectedZkBlockSlotsAssembly {
    pub(in crate::acceptance) fn slots(&self) -> &BlockSlots {
        &self.slots
    }

    pub(in crate::acceptance) fn region_vk(&self) -> &BlockRegionSidecarVk {
        self.region.vk()
    }

    /// Consume the only nonce authority, replace the explicitly deferred free
    /// inputs, and append the canonical direct transition plus `BLOCKHDR`
    /// tail. No ordinary witness wire is mutable through this API.
    pub(in crate::acceptance) fn seal_direct_tail(
        &mut self,
        b: &mut FieldR1csBuilder,
        sealed_header: &BlockHeader,
        end_accumulator: &ChainAccumulator,
    ) -> Result<(), DirectBlockSealError> {
        let seal = self
            .nonce_seal
            .take()
            .ok_or(DirectBlockSealError::AlreadySealed)?;
        seal.seal(sealed_header, end_accumulator)?;
        append_direct_block_tail(
            b,
            &self.slots.header,
            &self.slots.start_acc,
            &self.slots.end_acc,
            &self.parent_block_id,
        );
        Ok(())
    }

    pub(in crate::acceptance) fn into_region_binding(self) -> SelectedZkBlockRegionBinding {
        assert!(
            self.nonce_seal.is_none(),
            "selected block region cannot finalize before the direct nonce tail"
        );
        self.region
    }
}

pub(in crate::acceptance) fn finalize_selected_zk_block_region(
    assembly: SelectedZkBlockSlotsAssembly,
    total_vars: usize,
) -> Result<BlockRegionPreparation, RegionSidecarError> {
    assembly
        .into_region_binding()
        .finalize_after_block_build(SelectedBlockAssemblyFinalizationSeal(()), total_vars)
}

/// Canonical authorization entry. The proof bundle is owned and cannot be
/// omitted, replaced by a transparent proof, or selected by a runtime mode.
pub(in crate::acceptance) fn build_block_slots_selected_zk(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &HistoryStepBlockComponents,
    sealed_header: &BlockHeader,
    tier: usize,
    proofs: PreparedSelectedZkAuthorizations,
    parent_header: &BlockHeader,
    parent_block_id: &[LinExpr; 2],
) -> SelectedZkBlockSlotsAssembly {
    let mut assembly = build_block_slots_selected_zk_prefix(
        b,
        start_accumulator,
        end_accumulator,
        components,
        sealed_header,
        tier,
        proofs,
        parent_header,
        parent_block_id,
    );
    assembly
        .seal_direct_tail(b, sealed_header, end_accumulator)
        .expect("an immediate direct block assembly seals its exact input");
    assembly
}

/// Build every direct-Block row except the class-fixed direct tail. Only
/// the owning HistoryStep may retain this private capability across PoW.
/// The tail itself is nonce-free; the split exists so the owner appends it
/// after its public-IO pins in one canonical row order.
pub(in crate::acceptance) fn build_block_slots_selected_zk_prefix(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &HistoryStepBlockComponents,
    sealed_header: &BlockHeader,
    tier: usize,
    proofs: PreparedSelectedZkAuthorizations,
    parent_header: &BlockHeader,
    parent_block_id: &[LinExpr; 2],
) -> SelectedZkBlockSlotsAssembly {
    assert!(
        crate::region_sidecar::selected_zk_block_geometry(tier).is_some(),
        "selected backend tier is not canonical"
    );
    let mut assembly = build_selected_zk_block_slots_core(
        b,
        start_accumulator,
        end_accumulator,
        components,
        sealed_header,
        tier,
        proofs,
        parent_header,
        parent_block_id,
    );
    let region = assembly
        .selected_region
        .take()
        .expect("selected backend returned its opaque bound region");
    SelectedZkBlockSlotsAssembly {
        slots: assembly.slots,
        region,
        nonce_seal: Some(assembly.nonce_seal),
        parent_block_id: [parent_block_id[0].clone(), parent_block_id[1].clone()],
    }
}

fn build_selected_zk_block_slots_core(
    b: &mut FieldR1csBuilder,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &HistoryStepBlockComponents,
    sealed_header: &BlockHeader,
    tier: usize,
    authorization_proofs: PreparedSelectedZkAuthorizations,
    parent_header: &BlockHeader,
    parent_block_id: &[LinExpr; 2],
) -> BlockSlotsCoreAssembly {
    assert_eq!(
        components.tx_body_inputs.len(),
        components.tx_body_hashes.len()
    );
    let n_real_pages = components.tx_body_inputs.len().saturating_sub(1);
    assert_eq!(
        noid_chain::consensus::paged_spend::BlockProofClass::for_page_count(n_real_pages)
            .map(|class| class.page_capacity()),
        Some(tier),
        "selected Block capacity must match its physical page class"
    );

    let mut ledger = b.num_wires();

    // ---- Primary statement wires: exact header and accumulator boundary.
    let header = DirectHeaderTrace::alloc(b, sealed_header);
    let start_acc = AccumulatorWires::alloc(b, start_accumulator);
    let end_acc = AccumulatorWires::alloc(b, end_accumulator);

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: statement wires");
    use header_fields as hf;
    // Parent continuity and child accumulator fields bind directly to the
    // sealed header. The chain link runs through the derived parent block
    // id: the semantic start tip is glued to the same parent header by the
    // owning HistoryStep's parent seal.
    for lane in 0..2 {
        pin_eq(
            b,
            &parent_block_id[lane],
            &header.fields[hf::PREV_BLOCK_HASH + lane],
        );
    }
    pin_eq(
        b,
        &end_acc.active_slot_count,
        &header.fields[hf::ACTIVE_SLOT_COUNT],
    );
    pin_eq(b, &end_acc.alloc_counter, &header.fields[hf::ALLOC_COUNTER]);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: direct header boundary");
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
    let n_real_txs = components.tx_body_inputs.len();
    let tx_delta = 1;
    let cap_txs = tier + tx_delta;
    assert!(
        !components.tx_body_inputs.is_empty(),
        "selected Block carries a body"
    );
    let mut spine_natives: Vec<SpineInputs> = components.tx_body_inputs.clone();
    let mut hash_natives: Vec<[Block128; 2]> = components.tx_body_hashes.clone();
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
    // ---- Physical page liveness. Page/action/exact-state geometry follows
    // this prefix; logical authorization liveness is derived later by the
    // START..END scanner and is intentionally a separate quantity.
    let page_live_bits: Vec<LinExpr> = (0..tier)
        .map(|i| {
            let v = Block128::from(if i < n_real_pages { 1u128 } else { 0u128 });
            alloc_block(b, v)
        })
        .collect();
    for wire in &page_live_bits {
        let square = mul(b, wire, wire);
        pin_eq(b, &square, wire);
    }
    for index in 0..page_live_bits.len().saturating_sub(1) {
        let not_previous = page_live_bits[index].add_const(F128::ONE);
        let dead_then_live = mul(b, &page_live_bits[index + 1], &not_previous);
        pin_zero(b, &dead_then_live);
    }
    let body_user_slots = tier;

    // Coinbase L0 = parent tip. In a capacity class every user slot gets the
    // same live/ghost gated relation; the non-capacity path pins all real L0s
    // directly.
    bind_tx_epoch_anchors(
        b,
        parent_block_id,
        &end_acc.epoch_anchor_id,
        &spine_inputs,
        n_real_txs,
        tx_delta,
        Some(&page_live_bits),
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
    // ---- exact_state component + its statement anchors. The production
    // relation consumes the authoritative sibling frontier and derives the
    // fixed-capacity paired local/upper schedule.
    let structural_es = &components.exact_state;
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
    let parent_root = start_acc.state_root.clone();
    let child_root = [
        header.fields[hf::STATE_ROOT].clone(),
        header.fields[hf::STATE_ROOT + 1].clone(),
    ];
    let exact_state_depth = bind_exact_state_header_roots_dynamic(
        b,
        &exact_state.roots,
        &parent_root,
        &start_acc.log_slots,
        &child_root,
        &header.fields[hf::LOG_SLOTS],
    );

    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: exact-state");
    // ---- Physical page arithmetic followed by the fixed PagedSpend scan.
    // Pages keep the existing action/exact-state surface; only complete END
    // records enter logical tx-root, fee and authorization slots.
    let geometry = crate::region_sidecar::selected_zk_block_geometry(tier)
        .expect("selected authorization tier is canonical");
    assert_eq!(body_user_slots, geometry.tier);
    let n_auth_slots = geometry.auth_tiles;
    assert_eq!(n_auth_slots, geometry.auth_tiles);
    assert_eq!(tx_delta, 1, "selected body aliases begin after coinbase");
    assert_eq!(
        spine_inputs.len(),
        body_user_slots + tx_delta,
        "selected authorization requires every canonical body spine"
    );

    let mut page_surfaces = Vec::with_capacity(body_user_slots);
    let mut user_public_arithmetic = Vec::with_capacity(body_user_slots);
    for index in 0..body_user_slots {
        let body_index = index + tx_delta;
        let (surface, arithmetic) = append_page_action_surface(
            b,
            &spine_inputs[body_index],
            &page_live_bits[index],
            &mut action_candidates,
            &mut selected_input_bits,
            &mut selected_output_bits,
        );
        page_surfaces.push(surface);
        user_public_arithmetic.push(arithmetic);
    }
    let paged_spend = bind_paged_spend_stream(
        b,
        &spine_inputs[tx_delta..],
        &tx_hashes[tx_delta..],
        &page_live_bits,
        &page_surfaces,
        &user_public_arithmetic,
    );
    assert_eq!(paged_spend.groups.len(), n_auth_slots);
    assert_eq!(
        block_from_alias(b, &paged_spend.logical_count).0 as usize,
        components.authorization_inputs.len(),
        "native logical authorization count must equal the constrained END prefix"
    );
    let authorization_live_bits = paged_spend
        .groups
        .iter()
        .map(|group| group.live.clone())
        .collect::<Vec<_>>();
    let tx_count = alloc_block(
        b,
        Block128::from((components.authorization_inputs.len() + 1) as u128),
    );
    pin_u64_successor(b, &paged_spend.logical_count, &tx_count);

    // Coinbase plus compacted logical txids form the universal tx tree.
    assert!(
        !components.tx_root_inputs.is_empty(),
        "selected Block carries the canonical logical transaction root"
    );
    let logical_hash_natives = std::iter::once(components.tx_body_hashes[0])
        .chain(
            components
                .authorization_inputs
                .iter()
                .map(|input| input.tx_body_hash),
        )
        .collect::<Vec<_>>();
    let mut logical_hash_wires = Vec::with_capacity(tier + tx_delta);
    logical_hash_wires.push(tx_hashes[0].clone());
    logical_hash_wires.extend(
        paged_spend.groups[..tier]
            .iter()
            .map(|group| group.logical_txid.clone()),
    );
    let tx_root_region_data = Some(tx_root_region_capacity_handoff(
        b,
        &components.tx_root_inputs,
        &logical_hash_natives,
        &logical_hash_wires,
        &authorization_live_bits[..tier],
        tx_delta,
    ));
    let merkle_root = tx_root_region_data
        .as_ref()
        .expect("selected Meta-B logical tx-root handoff")
        .root_w
        .clone();
    let header_root = [
        header.fields[hf::TX_ROOT].clone(),
        header.fields[hf::TX_ROOT + 1].clone(),
    ];
    bind_tx_root_count_wrapper(b, &merkle_root, &tx_count, &header_root);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: PagedSpend+logical tx-root");

    let canonical_authorization =
        mint_canonical_selected_zk_authorization_capability(b, &paged_spend.groups);
    assert_eq!(
        user_public_arithmetic.len(),
        body_user_slots,
        "one public-arithmetic trace per physical user body slot"
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: page arithmetic+logical auth");
    let _fee_arithmetic = bind_block_fee_arithmetic(
        b,
        &paged_spend.groups[..tier],
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
    let live_input_sum = pin_u64_sum(b, &selected_input_bits);
    let output_sum = pin_u64_sum(b, &selected_output_bits);

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
        &header.fields[hf::HEIGHT],
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

    let slots = BlockSlots {
        header,
        start_acc,
        end_acc,
        spine_inputs,
        tx_hashes,
        page_live_bits,
        authorization_live_bits,
        compacted_actions,
        exact_state,
    };
    BlockSlotsCoreAssembly {
        slots,
        selected_region,
        nonce_seal: DirectBlockNonceSeal {
            template_header: *sealed_header,
            start_accumulator: start_accumulator.clone(),
            parent_header: *parent_header,
        },
    }
}

/// The class-fixed relation suffix. Nonce-free: every gadget is fully
/// determined by the semantic template, the start boundary and the derived
/// parent block id supplied by the owning HistoryStep's parent seal.
fn append_direct_block_tail(
    b: &mut FieldR1csBuilder,
    header: &DirectHeaderTrace,
    start_accumulator: &AccumulatorWires,
    end_accumulator: &AccumulatorWires,
    parent_block_id: &[LinExpr; 2],
) {
    use header_fields as hf;

    let mut ledger = b.num_wires();
    let child = DirectChildWires {
        semantic_id: header.expected_semantic_id.clone(),
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
    build_direct_accumulator_transition_slot(
        b,
        start_accumulator,
        &child,
        end_accumulator,
        parent_block_id,
    );

    // Exact `SEMHDR` binding over the same semantic header wires. PoW,
    // difficulty and the nonce-bearing chain-link id remain exclusively in
    // the permanent native header path; the child step's parent seal derives
    // and pins the link id in-circuit one height later.
    bind_direct_semantic_id(b, header);
    debug_assert_eq!(
        b.num_wires() - ledger,
        DIRECT_BLOCK_TAIL_ROWS,
        "canonical direct tail row drift"
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "slots: direct accumulator + header hash");
}

#[cfg(test)]
mod tx_epoch_anchor_tests {
    use super::*;
    use noid_core::TowerField;

    fn tail_parent_header(height: u64) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0x10; 32],
            state_root: [0x22; 32],
            tx_root: [0x2A; 32],
            timestamp: height * 10,
            height,
            miner_address: noid_poseidon2b::primitives::Address([0x66; 32]),
            nonce: height as u128,
            difficulty_target: [0xFF; 32],
            log_slots: 8,
            active_slot_count: 7,
            alloc_counter: 9,
        }
    }

    fn tail_start(parent: &BlockHeader) -> ChainAccumulator {
        ChainAccumulator {
            height: parent.height,
            tip_semantic_id: noid_chain::block_header::semantic_header_id(parent),
            state_root: parent.state_root,
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
            epoch_anchor_id: [0x33; 32],
        }
    }

    fn tail_child(parent: &BlockHeader, nonce: u128) -> BlockHeader {
        BlockHeader {
            prev_block_hash: noid_chain::hash_block_header(parent),
            state_root: [0x44; 32],
            tx_root: [0x55; 32],
            timestamp: parent.timestamp + 10,
            height: parent.height + 1,
            miner_address: noid_poseidon2b::primitives::Address([0x66; 32]),
            nonce,
            difficulty_target: [0xFF; 32],
            log_slots: parent.log_slots,
            active_slot_count: 8,
            alloc_counter: 10,
        }
    }

    fn direct_tail_fixture(
        parent: &BlockHeader,
        sealed_header: &BlockHeader,
        start: &ChainAccumulator,
        end: &ChainAccumulator,
    ) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>, usize) {
        let mut builder = FieldR1csBuilder::new();
        let header = DirectHeaderTrace::alloc(&mut builder, sealed_header);
        let start_wires = AccumulatorWires::alloc(&mut builder, start);
        let end_wires = AccumulatorWires::alloc(&mut builder, end);
        let parent_block_id = digest_lanes(&noid_chain::hash_block_header(parent))
            .map(|lane| alloc_block(&mut builder, lane));

        // Represents arbitrary HistoryStep rows placed between the primary
        // statement and the class-fixed direct suffix.
        for index in 0..17u64 {
            builder.alloc_f128(F128 {
                lo: index + 1,
                hi: 0,
            });
        }
        let seal = DirectBlockNonceSeal {
            template_header: *sealed_header,
            start_accumulator: start.clone(),
            parent_header: *parent,
        };
        seal.seal(sealed_header, end)
            .expect("exact sealed template boundary");
        let before_tail = builder.num_wires();
        append_direct_block_tail(
            &mut builder,
            &header,
            &start_wires,
            &end_wires,
            &parent_block_id,
        );
        let tail_rows = builder.num_wires() - before_tail;
        let (matrix, witness) = builder.build();
        (matrix, witness, tail_rows)
    }

    #[test]
    fn direct_tail_is_nonce_free_across_the_epoch_edge() {
        // Parent heights 143 (child 144: boundary block keeps the previous
        // anchor) and 144 (child 145: anchor becomes the derived parent id).
        for parent_height in [143u64, 144] {
            let parent = tail_parent_header(parent_height);
            let start = tail_start(&parent);
            let template = tail_child(&parent, 0);
            let mut renonced = template;
            renonced.nonce = 0xDEAD_BEEF_CAFE_BABEu128;

            let end = start.advance(&parent, &template).unwrap();
            let renonced_end = start.advance(&parent, &renonced).unwrap();
            // The complete boundary is nonce-invariant.
            assert_eq!(end, renonced_end);
            if parent_height == 144 {
                assert_eq!(end.epoch_anchor_id, noid_chain::hash_block_header(&parent));
            } else {
                assert_eq!(end.epoch_anchor_id, start.epoch_anchor_id);
            }

            let (matrix, witness, tail_rows) =
                direct_tail_fixture(&parent, &template, &start, &end);
            let (renonced_matrix, renonced_witness, renonced_tail_rows) =
                direct_tail_fixture(&parent, &renonced, &start, &renonced_end);

            assert_eq!(tail_rows, DIRECT_BLOCK_TAIL_ROWS);
            assert_eq!(renonced_tail_rows, tail_rows);
            assert_eq!(
                matrix.structural_statement_digest(),
                renonced_matrix.structural_statement_digest()
            );
            // The witness itself is identical for every nonce of one
            // template: the relation is nonce-free.
            assert_eq!(witness, renonced_witness);
            assert!(matrix.satisfies(&witness));
        }
    }

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
            tip_semantic_id: [0x11; 32],
            state_root: [0x22; 32],
            log_slots: 24,
            active_slot_count: 7,
            alloc_counter: 9,
            epoch_anchor_id: [0x33; 32],
        }
    }

    const TEST_PARENT_BLOCK_ID: [u8; 32] = [0x66; 32];

    fn bodies(start: &ChainAccumulator) -> Vec<SpineInputs> {
        let mut coinbase = SpineInputs {
            leaves: [[Block128::ZERO; 2]; noid_tx::body_hash::BODY_HASH_LEAVES],
        };
        coinbase.leaves[noid_tx::body_hash::TX8X2_LEAF_EPOCH_ANCHOR] =
            digest_lanes(&TEST_PARENT_BLOCK_ID);
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
        let parent_id = digest_lanes(&TEST_PARENT_BLOCK_ID).map(|lane| alloc_block(&mut b, lane));
        bind_tx_epoch_anchors(
            &mut b,
            &parent_id,
            &start.epoch_anchor_id,
            &traces,
            1 + real_users,
            1,
            Some(&live_bits),
        );
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
        let parent_id = digest_lanes(&TEST_PARENT_BLOCK_ID).map(|lane| alloc_block(&mut b, lane));
        bind_tx_epoch_anchors(
            &mut b,
            &parent_id,
            &start_w.epoch_anchor_id,
            &traces,
            2,
            1,
            Some(&live_bits[..255]),
        );
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
