// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Lightweight, allocation-only roofline for the selected authorization
//! ZK-capsule geometry.
//!
//! This executable checks dyadic domains, path carriers, transcript-period
//! screening allowances, and a conservative serialized-payload projection.
//! It does not construct the verifier relation itself.  Its exact replacement
//! ledger is cross-checked by `selected_zk_b255_measurement`, whose canonical
//! Block build is the measured R1CS authority.

use noid_fri_binius::capsule::CAPSULE_CAP_DEPTH;
use noid_fri_binius::ZK_AUTH_CAPSULE_GEOMETRY;
use noid_gkr::{OWNER_AUTH_NUM_VARS, OWNER_AUTH_STATE_ROUND_DEGREE};
use noid_recursive::acceptance::shape::ShapeClass;
use noid_recursive::acceptance::trace::zk_affine_tail::ZK_AFFINE_TAIL_SELECTOR_ROWS;
use noid_recursive::acceptance::trace::zk_authorization_candidate::{
    ZK_AUTHORIZATION_CANDIDATE_EXTERNAL_BRIDGE_ROWS, ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS,
};
use noid_recursive::acceptance::trace::zk_phase_b_upper_link::ZK_PHASE_B_UPPER_LINK_ROWS_OVER_ACTIVE;
use noid_recursive::acceptance::trace::zk_query_carriers::ZK_QUERY_CARRIER_ROWS_OVER_PREVIOUS;
use noid_recursive::acceptance::zk_auth_capsule_schedule::{
    ZkAuthCapsuleDuplexSchedules, ZK_AUTH_MAIN_COMPILED_SLOTS, ZK_AUTH_MAIN_DYNAMIC_LANES,
    ZK_AUTH_MAIN_SQUEEZES, ZK_AUTH_OWNER_COMPILED_SLOTS, ZK_AUTH_OWNER_DYNAMIC_LANES,
    ZK_AUTH_OWNER_SQUEEZES, ZK_AUTH_REJECTED_SINGLE_CHANNEL_SLOTS,
};

const B255_TIER: usize = 255;
const B255_CURRENT_BLOCK_ROWS: usize = 13_649_801;
const B255_BLOCK_SCREENING_CEILING: usize = 15_213_508;
const M24_ROWS: usize = 1 << 24;
// Exact current full-Block ledger boundary immediately before Main-C. Main-C
// allocates six columns aligned to 2^16, so a raw pre-column delta must be
// rounded at this boundary before it can be compared with the full relation.
const B255_CURRENT_PRE_MAIN_C_ROWS: usize = 12_036_100;
const MAIN_C_COLUMN_ALIGNMENT: usize = 1 << 16;
// Owner-C-only deletions do not survive the following Wallet-A 2^19
// alignment. These are exact analytical checkpoints from the current ledger.
const B255_CURRENT_PRE_WALLET_A_ROWS: usize = 1_904_640;
const B255_OLD_OWNER_GROUPS_REMOVED_PRE_WALLET_A_ROWS: usize = 1_685_248;
const WALLET_A_COLUMN_ALIGNMENT: usize = 1 << 19;
const CURRENT_OWNER_C_COLUMN_LOG: usize = 16;
const FUTURE_OWNER_C_COLUMN_LOG: usize = 15;
const OWNER_C_COMMITTED_COLUMNS: usize = 6;

const CURRENT_OWNER_TRANSCRIPT_SLOTS: usize = 164;
// Release geometry uses seven packed query seeds.  The selected transcript's
// exact FRI commit/challenge ordering still remains inside the m8 period.
const CURRENT_MAIN_TRANSCRIPT_SLOTS: usize = 178;
const TRANSCRIPT_PADDED_PERIOD: usize = 256;
const CURRENT_QUERY_SEED_COUNT: usize = 7;

// Exact split-channel schedule model. Main absorbs all four lanes of the
// closed Owner poststate, so it is causally bound to the source cap without a
// second cap absorb. The bridge is derived and is not proof payload.
const CURRENT_OWNER_DYNAMIC_FIELDS: usize = 222;
const CURRENT_MAIN_DYNAMIC_FIELDS: usize = 335;
const CURRENT_OWNER_SQUEEZES: usize = 48;
const CURRENT_MAIN_SQUEEZES: usize = 16;

// Exact isolated trace deltas relative to the active capsule algebra. The
// 16-coefficient affine tail evaluates by a four-coordinate Horner tree in
// 15 rows; the active rate-2 terminal selector already costs two rows.
const CURRENT_RATE2_TAIL_SELECTOR_MULTIPLICATIONS_PER_QUERY: usize = 2;
// Query-indexed affine twiddles are non-constant trace expressions. Each
// inverse butterfly therefore costs two rows rather than the active window
// fold's one. Gamma+source adds seven rows and mid adds fifteen.
const AFFINE_FOLD_DELTA_MULTIPLICATIONS_PER_QUERY: usize = 22;
// Incremental work relative to the active cap32/root geometry. Source remains
// cap32. Mid root->cap2 adds one selector on each digest lane. Power-of-two
// depth-eight paths expose each root as C+CR+D(CR+SIB), one multiplication per
// digest lane and path.
const MID_CAP_SELECTOR_DELTA_MULTIPLICATIONS_PER_QUERY: usize = 2;
const COMPOSITE_ROOT_MULTIPLICATIONS_PER_QUERY: usize = 4;
// Potential old-code credit, reported separately and never applied to the
// safety subtotal. The active five-bit rate-coset equality tensor costs 31
// rows per query.
const CURRENT_RC_TENSOR_ROWS_PER_QUERY: usize = 31;

// Exact measured legacy checkpoints used to screen the full selected
// replacement.  The selected total below is now independently reproduced by
// the canonical feature-gated Block measurement, including every checkpoint.
const B255_LEGACY_BLOCK_IO_ROWS: usize = 64;
const B255_LEGACY_STATEMENT_ROWS: usize = 40;
const B255_LEGACY_CLAIM_HASH_ROWS: usize = 135_752;
const B255_LEGACY_SPINE_ROWS: usize = 8_704;
const B255_LEGACY_LIVENESS_ROWS: usize = 18_758;
const B255_LEGACY_TX_ROOT_ROWS: usize = 1_234;
const B255_LEGACY_EXACT_STATE_ROWS: usize = 16_115;
const B255_LEGACY_AFTER_EXACT_STATE_ROWS: usize = 180_667;
const B255_LEGACY_AUTH_AND_PUBLIC_ROWS: usize = 727_227;
const B255_LEGACY_FEE_ROWS: usize = 115_073;
const B255_LEGACY_OWNER_REGION_ROWS: usize = 881_161;
const B255_LEGACY_META_NATIVE_BRIDGE_ROWS: usize = 512;
const B255_LEGACY_WALLET_META_REGION_ROWS: usize = 10_637_568;
const B255_LEGACY_ACTION_ALLOCATOR_ROWS: usize = 746_700;
const B255_LEGACY_PAIRED_TOPOLOGY_ROWS: usize = 221_650;
const B255_LEGACY_STRUCTURAL_FRONTIER_ROWS: usize = 42_882;
const B255_LEGACY_ACCUMULATOR_AND_HEADER_ROWS: usize = 96_853;
const B255_BLOCK_IO_PIN_ROWS: usize = 20;

const LEGACY_OWNER_PUBLIC_INPUT_ROWS_PER_AUTH: usize = 4;
const LEGACY_OWNER_PROOF_ROWS_PER_AUTH: usize = OWNER_AUTH_NUM_VARS
    * OWNER_AUTH_STATE_ROUND_DEGREE
    + 5 // reduced main state and four lane values
    + 3 * (2 * OWNER_AUTH_NUM_VARS + 1) // shift, boundary, and batch carriers
    + 2 * (1 << CAPSULE_CAP_DEPTH); // two field lanes per commitment-cap hash
const LEGACY_OWNER_BODY_HASH_PIN_ROWS_PER_AUTH: usize = 2;

const SELECTED_WALLET_A_COLUMNS: usize = 6;
const SELECTED_WALLET_B_COLUMNS: usize = 9;
const SELECTED_META_A_COLUMNS: usize = 8;
const SELECTED_META_B_COLUMNS: usize = 9;
const SELECTED_OWNER_COLUMNS: usize = 6;
const SELECTED_MAIN_COLUMNS: usize = 6;
const SELECTED_WALLET_A_LOG: usize = 19;
const SELECTED_WALLET_B_LOG: usize = 18;
const SELECTED_META_A_LOG: usize = 15;
const SELECTED_META_B_LOG: usize = 17;
const SELECTED_OWNER_LOG: usize = 15;
const SELECTED_MAIN_LOG: usize = 16;

const B255_PAIRED_COPY_AND_GHOST_ROWS: usize = 200_000;
const B255_META_A_EXACT_LEAF_PIN_ROWS: usize = 18_372;
const B255_META_A_SPINE_PIN_ROWS: usize = 9_728;
const B255_META_B_TX_ROOT_PIN_ROWS: usize = 3_072;
const B255_UNCHANGED_META_PIN_ROWS: usize =
    B255_META_A_EXACT_LEAF_PIN_ROWS + B255_META_A_SPINE_PIN_ROWS + B255_META_B_TX_ROOT_PIN_ROWS;

const SELECTED_STATEMENT_PIN_ROWS_PER_AUTH: usize = 4;
const SELECTED_DIGEST_PIN_ROWS_PER_AUTH: usize = 64 * 2 * 2;
const SELECTED_ROOT_PIN_ROWS_PER_AUTH: usize = 64 * 2 * 2;
const SELECTED_METADATA_PIN_ROWS_PER_AUTH: usize = 64 * 2 * 2;
const SELECTED_WRAPPER_ROWS_PER_AUTH: usize = SELECTED_STATEMENT_PIN_ROWS_PER_AUTH
    + ZK_AUTHORIZATION_CANDIDATE_EXTERNAL_BRIDGE_ROWS
    + SELECTED_DIGEST_PIN_ROWS_PER_AUTH
    + SELECTED_ROOT_PIN_ROWS_PER_AUTH
    + SELECTED_METADATA_PIN_ROWS_PER_AUTH;
const SELECTED_TILE_ROWS_PER_AUTH: usize =
    ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS + SELECTED_WRAPPER_ROWS_PER_AUTH;
// PAD255 has no canonical body aliases.  Its four public-statement values are
// therefore first materialized as constant-pinned witness wires and then fed
// through the same four statement pins as every other tile.
const SELECTED_PAD_MATERIALIZATION_ROWS: usize = 4;
const B255_SELECTED_REPLACEMENT_TARGET_ROWS: usize = 13_058_193;

const DIGEST_BYTES: usize = 32;
const CURRENT_WALLET_PROOF_BYTES: usize = 49_792;
const CURRENT_AUTH_GKR_BATCH_FIXED_BYTES: usize = 2_432;
const FUTURE_ZK_MAIN_PHASE_A_SIGMA_FIXED_BYTES: usize = 2_240;
const TREE_AND_TAIL_FIXED_DELTA_BYTES: usize = 256;
const CURRENT_PATH_SIBLINGS: usize = 288;
const PROOF_SIZE_TARGET_BYTES: usize = 64 * 1024;

fn exact_log2(value: usize, label: &str) -> usize {
    assert!(value.is_power_of_two(), "{label} must be dyadic");
    value.trailing_zeros() as usize
}

fn align_up(value: usize, alignment: usize) -> usize {
    assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .expect("alignment overflow")
        & !(alignment - 1)
}

/// Maximum authentication hashes for exactly `k` distinct leaves in one
/// binary subtree of `path_depth`. Index zero is the empty selection.
fn tree_multiproof_maxima(path_depth: usize, max_queries: usize) -> Vec<Option<usize>> {
    let mut previous = vec![None; max_queries + 1];
    previous[0] = Some(0);
    if max_queries > 0 {
        previous[1] = Some(0);
    }

    for depth in 1..=path_depth {
        let half_capacity = 1usize << (depth - 1);
        let mut next = vec![None; max_queries + 1];
        next[0] = Some(0);
        for selected in 1..=max_queries.min(2 * half_capacity) {
            for left in 0..=selected {
                let right = selected - left;
                if left > half_capacity || right > half_capacity {
                    continue;
                }
                let (Some(left_cost), Some(right_cost)) = (previous[left], previous[right]) else {
                    continue;
                };
                // If exactly one child subtree is empty, its root must ship as
                // one authentication hash. If both are occupied they merge.
                let sibling = usize::from(left == 0 || right == 0);
                let cost = left_cost + right_cost + sibling;
                next[selected] = Some(next[selected].map_or(cost, |old| old.max(cost)));
            }
        }
        previous = next;
    }
    previous
}

/// Exact worst multiproof sibling count across a forest of public cap roots.
/// Repeated transcript queries can only reduce the number of distinct leaves,
/// so the maximum ranges over every distinct count up to `query_count`.
fn forest_multiproof_max_siblings(
    path_depth: usize,
    cap_roots: usize,
    query_count: usize,
) -> usize {
    let tree = tree_multiproof_maxima(path_depth, query_count);
    let mut forest = vec![None; query_count + 1];
    forest[0] = Some(0);
    for _ in 0..cap_roots {
        let mut next: Vec<Option<usize>> = vec![None; query_count + 1];
        for used in 0..=query_count {
            let Some(forest_cost) = forest[used] else {
                continue;
            };
            for added in 0..=query_count - used {
                let Some(tree_cost) = tree[added] else {
                    continue;
                };
                let cost = forest_cost + tree_cost;
                let total = used + added;
                next[total] = Some(next[total].map_or(cost, |old| old.max(cost)));
            }
        }
        forest = next;
    }
    forest.into_iter().flatten().max().unwrap_or(0)
}

fn main() {
    let g = ZK_AUTH_CAPSULE_GEOMETRY;
    let schedules = ZkAuthCapsuleDuplexSchedules::selected();
    let owner_layout = schedules.owner_layout();
    let main_layout = schedules.main_layout();
    let auth_slots = ShapeClass { tier: B255_TIER }.authorization_capacity();
    assert_eq!(auth_slots, 256, "B255 includes one authorization PAD");

    // Wallet-A keeps exactly the current 2^19 symbol-cell domain.
    assert_eq!(g.source_leaf_symbols, 16, "joint leaf remains 8+8 symbols");
    assert_eq!(g.wallet_a_symbols_per_auth(), 2_048);
    assert_eq!(
        g.wallet_a_symbols_per_auth(),
        g.query_count() * (g.source_leaf_symbols + g.mid_leaf_symbols)
    );
    let wallet_a_domain = auth_slots * g.wallet_a_symbols_per_auth();
    assert_eq!(exact_log2(wallet_a_domain, "Wallet-A domain"), 19);

    // Both depth-eight Merkle paths exactly fill the existing stride. Their
    // roots use the core FF family's no-tail composite handoff.
    assert_eq!((g.source_path_depth, g.mid_path_depth), (8, 8));
    assert_eq!(g.wallet_b_legs, 2);
    assert_eq!(g.wallet_b_stride, 8);
    for (label, depth) in [("source", g.source_path_depth), ("mid", g.mid_path_depth)] {
        assert!(depth <= g.wallet_b_stride, "{label} path overflow");
        assert_eq!(depth.next_power_of_two(), g.wallet_b_stride);
    }
    assert!(!g.source_uses_root_copy_tail);
    assert!(!g.mid_uses_root_copy_tail);
    assert_eq!(g.wallet_b_slots_per_auth(), 1_024);
    let wallet_b_domain = auth_slots * g.wallet_b_slots_per_auth();
    assert_eq!(exact_log2(wallet_b_domain, "Wallet-B domain"), 18);

    // Uniform joint-leaf queries consume 13 bits and the same seven packed
    // seeds as the active capsule. Source directions carry q0..q7, mid
    // directions q4..q11, and one auxiliary cell carries q12.
    assert_eq!(g.query_width_bits, g.source_tree_depth);
    assert_eq!(g.query_width_bits, 13);
    assert_eq!(g.query_seed_count(), CURRENT_QUERY_SEED_COUNT);
    assert_eq!(g.query_bits_with_existing_carriers, 12);
    assert_eq!(g.query_bits_requiring_aux_carrier, 1);

    // Compiled schedule screen. Owner closes on a fixed full block and all
    // four output-state lanes are pinned into Main before sigma/gamma. Cap
    // roots remain separately pinned to the Merkle obligations.
    assert_eq!(g.source_transcript_delta_lanes(), 0);
    assert_eq!(g.mid_transcript_delta_lanes(), 2);
    assert_eq!(g.tail_transcript_delta_lanes(), 14);
    assert_eq!(owner_layout.slots.len(), ZK_AUTH_OWNER_COMPILED_SLOTS);
    assert_eq!(main_layout.slots.len(), ZK_AUTH_MAIN_COMPILED_SLOTS);
    assert_eq!(ZK_AUTH_OWNER_COMPILED_SLOTS, 118);
    assert_eq!(ZK_AUTH_MAIN_COMPILED_SLOTS, 177);
    assert!(ZK_AUTH_OWNER_COMPILED_SLOTS < CURRENT_OWNER_TRANSCRIPT_SLOTS);
    assert!(ZK_AUTH_MAIN_COMPILED_SLOTS < CURRENT_MAIN_TRANSCRIPT_SLOTS);
    assert!(ZK_AUTH_OWNER_COMPILED_SLOTS < 128);
    assert!(ZK_AUTH_MAIN_COMPILED_SLOTS < TRANSCRIPT_PADDED_PERIOD);
    assert_eq!(ZK_AUTH_REJECTED_SINGLE_CHANNEL_SLOTS, 292);
    assert_eq!(
        ZK_AUTH_REJECTED_SINGLE_CHANNEL_SLOTS.next_power_of_two(),
        512
    );
    assert_eq!(
        (CURRENT_OWNER_DYNAMIC_FIELDS + CURRENT_MAIN_DYNAMIC_FIELDS)
            - (ZK_AUTH_OWNER_DYNAMIC_LANES + ZK_AUTH_MAIN_DYNAMIC_LANES),
        67
    );
    assert_eq!(
        (CURRENT_OWNER_SQUEEZES + CURRENT_MAIN_SQUEEZES)
            - (ZK_AUTH_OWNER_SQUEEZES + ZK_AUTH_MAIN_SQUEEZES),
        12
    );

    // Exact combinatorial upper bounds for the canonical batched paths.
    let source_siblings = forest_multiproof_max_siblings(
        g.source_path_depth,
        1 << g.source_cap_depth,
        g.query_count(),
    );
    let mid_siblings =
        forest_multiproof_max_siblings(g.mid_path_depth, 1 << g.mid_cap_depth, g.query_count());
    assert_eq!((source_siblings, mid_siblings), (448, 192));

    // Conservative payload model, not a wire bound: future fixed protocol
    // fields replace the current AuthGKR+batch fixed section; cap/mid/tail add
    // 256 bytes; exact path maxima add 352 digests.
    assert_eq!(source_siblings + mid_siblings, 640);
    let fixed_protocol_delta = FUTURE_ZK_MAIN_PHASE_A_SIGMA_FIXED_BYTES as isize
        - CURRENT_AUTH_GKR_BATCH_FIXED_BYTES as isize;
    assert_eq!(fixed_protocol_delta, -192);
    let path_delta_bytes = (source_siblings + mid_siblings - CURRENT_PATH_SIBLINGS) * DIGEST_BYTES;
    assert_eq!(path_delta_bytes, 11_264);
    let candidate_payload_bytes = (CURRENT_WALLET_PROOF_BYTES as isize
        + fixed_protocol_delta
        + TREE_AND_TAIL_FIXED_DELTA_BYTES as isize
        + path_delta_bytes as isize) as usize;
    assert_eq!(candidate_payload_bytes, 61_120);
    assert!(candidate_payload_bytes <= PROOF_SIZE_TARGET_BYTES);
    let unassigned_serialization_headroom = PROOF_SIZE_TARGET_BYTES - candidate_payload_bytes;

    // Isolated exact recursive-algebra deltas. This is still not the complete
    // future verifier relation, but unlike a raw addition it respects the
    // current Main-C 2^16 column boundary.
    let tail_selector_delta = g.query_count()
        * auth_slots
        * (ZK_AFFINE_TAIL_SELECTOR_ROWS - CURRENT_RATE2_TAIL_SELECTOR_MULTIPLICATIONS_PER_QUERY);
    let affine_fold_delta =
        g.query_count() * auth_slots * AFFINE_FOLD_DELTA_MULTIPLICATIONS_PER_QUERY;
    let path_and_carrier_delta = g.query_count()
        * auth_slots
        * (MID_CAP_SELECTOR_DELTA_MULTIPLICATIONS_PER_QUERY
            + COMPOSITE_ROOT_MULTIPLICATIONS_PER_QUERY)
        + auth_slots * ZK_QUERY_CARRIER_ROWS_OVER_PREVIOUS;
    assert_eq!(tail_selector_delta, 212_992);
    assert_eq!(affine_fold_delta, 360_448);
    assert_eq!(path_and_carrier_delta, 180_224);
    let upper_linkage_delta = auth_slots * ZK_PHASE_B_UPPER_LINK_ROWS_OVER_ACTIVE;
    assert_eq!(upper_linkage_delta, 3_584);
    let raw_geometry_delta =
        tail_selector_delta + affine_fold_delta + path_and_carrier_delta + upper_linkage_delta;
    assert_eq!(raw_geometry_delta, 757_248);
    let aligned_geometry_delta =
        align_up(
            B255_CURRENT_PRE_MAIN_C_ROWS + raw_geometry_delta,
            MAIN_C_COLUMN_ALIGNMENT,
        ) - align_up(B255_CURRENT_PRE_MAIN_C_ROWS, MAIN_C_COLUMN_ALIGNMENT);
    assert_eq!(aligned_geometry_delta, 786_432);
    let aligned_static_rows = B255_CURRENT_BLOCK_ROWS + aligned_geometry_delta;
    assert_eq!(aligned_static_rows, 14_436_233);
    assert!(aligned_static_rows <= B255_BLOCK_SCREENING_CEILING);
    assert!(B255_BLOCK_SCREENING_CEILING < M24_ROWS);
    assert!(aligned_static_rows < M24_ROWS);
    let row_screen_headroom = B255_BLOCK_SCREENING_CEILING - aligned_static_rows;
    let raw_m24_headroom = M24_ROWS - aligned_static_rows;

    // Deleting every old shift/boundary/batch group still lands Wallet-A at
    // the same 2^19 boundary, so the safety subtotal credits zero Owner-C
    // rows until the replacement relation is materialized in the full block.
    assert_eq!(
        align_up(B255_CURRENT_PRE_WALLET_A_ROWS, WALLET_A_COLUMN_ALIGNMENT),
        align_up(
            B255_OLD_OWNER_GROUPS_REMOVED_PRE_WALLET_A_ROWS,
            WALLET_A_COLUMN_ALIGNMENT,
        )
    );
    let owner_c_surviving_credit = 0usize;
    // The new m7 Owner transcript makes the tiled B255 Owner-C columns m15
    // instead of m16. That six-column reduction alone is also swallowed by
    // the same Wallet-A boundary. Combining it with unmaterialized verifier
    // replacements would be speculative, so no mixed credit is taken.
    let owner_c_column_raw_credit = OWNER_C_COMMITTED_COLUMNS
        * ((1usize << CURRENT_OWNER_C_COLUMN_LOG) - (1usize << FUTURE_OWNER_C_COLUMN_LOG));
    assert_eq!(owner_c_column_raw_credit, 196_608);
    assert_eq!(
        align_up(B255_CURRENT_PRE_WALLET_A_ROWS, WALLET_A_COLUMN_ALIGNMENT),
        align_up(
            B255_CURRENT_PRE_WALLET_A_ROWS - owner_c_column_raw_credit,
            WALLET_A_COLUMN_ALIGNMENT,
        )
    );

    // The old rate-coset tensor would survive Main-C alignment, but remains a
    // separately reported opportunity rather than a safety assumption.
    let rc_tensor_raw_credit = g.query_count() * auth_slots * CURRENT_RC_TENSOR_ROWS_PER_QUERY;
    assert_eq!(rc_tensor_raw_credit, 507_904);
    let rc_tensor_aligned_credit = align_up(B255_CURRENT_PRE_MAIN_C_ROWS, MAIN_C_COLUMN_ALIGNMENT)
        - align_up(
            B255_CURRENT_PRE_MAIN_C_ROWS - rc_tensor_raw_credit,
            MAIN_C_COLUMN_ALIGNMENT,
        );
    assert_eq!(rc_tensor_aligned_credit, 524_288);

    // Full replacement target.  First reproduce the measured legacy
    // top-level ledger so none of its non-authorization rows can silently
    // disappear from this calculation.
    let legacy_after_exact_state = B255_LEGACY_BLOCK_IO_ROWS
        + B255_LEGACY_STATEMENT_ROWS
        + B255_LEGACY_CLAIM_HASH_ROWS
        + B255_LEGACY_SPINE_ROWS
        + B255_LEGACY_LIVENESS_ROWS
        + B255_LEGACY_TX_ROOT_ROWS
        + B255_LEGACY_EXACT_STATE_ROWS;
    assert_eq!(legacy_after_exact_state, B255_LEGACY_AFTER_EXACT_STATE_ROWS);
    let reconstructed_legacy_rows = legacy_after_exact_state
        + B255_LEGACY_AUTH_AND_PUBLIC_ROWS
        + B255_LEGACY_FEE_ROWS
        + B255_LEGACY_OWNER_REGION_ROWS
        // The outer wallet/meta checkpoint includes the 512 native spine-root
        // bridge rows itemized by its first internal ledger mark.
        + B255_LEGACY_WALLET_META_REGION_ROWS
        + B255_LEGACY_ACTION_ALLOCATOR_ROWS
        + B255_LEGACY_PAIRED_TOPOLOGY_ROWS
        + B255_LEGACY_STRUCTURAL_FRONTIER_ROWS
        + B255_LEGACY_ACCUMULATOR_AND_HEADER_ROWS
        + B255_BLOCK_IO_PIN_ROWS;
    assert_eq!(reconstructed_legacy_rows, B255_CURRENT_BLOCK_ROWS);

    assert_eq!(LEGACY_OWNER_PROOF_ROWS_PER_AUTH, 216);
    let removed_legacy_owner_carrier_rows = auth_slots
        * (LEGACY_OWNER_PUBLIC_INPUT_ROWS_PER_AUTH
            + LEGACY_OWNER_PROOF_ROWS_PER_AUTH
            + LEGACY_OWNER_BODY_HASH_PIN_ROWS_PER_AUTH);
    assert_eq!(removed_legacy_owner_carrier_rows, 56_832);
    let retained_public_arithmetic_rows =
        B255_LEGACY_AUTH_AND_PUBLIC_ROWS - removed_legacy_owner_carrier_rows;
    assert_eq!(retained_public_arithmetic_rows, 670_395);

    assert_eq!(B255_UNCHANGED_META_PIN_ROWS, 31_172);
    assert_eq!(SELECTED_WRAPPER_ROWS_PER_AUTH, 776);
    assert_eq!(SELECTED_TILE_ROWS_PER_AUTH, 12_241);
    let selected_all_tiles_rows = auth_slots * SELECTED_TILE_ROWS_PER_AUTH;
    assert_eq!(selected_all_tiles_rows, 3_133_696);

    // The common allocator owns all six children and places them in descending
    // domain order.  Independent Owner/Wallet/Meta allocators would change the
    // alignment gaps and must fail the eventual production checkpoint gate.
    let selected_after_public_and_fee =
        B255_LEGACY_AFTER_EXACT_STATE_ROWS + retained_public_arithmetic_rows + B255_LEGACY_FEE_ROWS;
    assert_eq!(selected_after_public_and_fee, 966_135);
    let selected_before_columns =
        selected_after_public_and_fee + B255_LEGACY_META_NATIVE_BRIDGE_ROWS;
    assert_eq!(selected_before_columns, 966_647);

    let selected_wallet_a_start = align_up(selected_before_columns, 1 << SELECTED_WALLET_A_LOG);
    assert_eq!(selected_wallet_a_start, 1_048_576);
    let selected_after_wallet_a =
        selected_wallet_a_start + SELECTED_WALLET_A_COLUMNS * (1 << SELECTED_WALLET_A_LOG);
    assert_eq!(selected_after_wallet_a, 4_194_304);

    let selected_wallet_b_start = align_up(selected_after_wallet_a, 1 << SELECTED_WALLET_B_LOG);
    assert_eq!(selected_wallet_b_start, selected_after_wallet_a);
    let selected_after_wallet_b =
        selected_wallet_b_start + SELECTED_WALLET_B_COLUMNS * (1 << SELECTED_WALLET_B_LOG);
    assert_eq!(selected_after_wallet_b, 6_553_600);

    let selected_meta_b_start = align_up(selected_after_wallet_b, 1 << SELECTED_META_B_LOG);
    assert_eq!(selected_meta_b_start, selected_after_wallet_b);
    let selected_after_meta_b =
        selected_meta_b_start + SELECTED_META_B_COLUMNS * (1 << SELECTED_META_B_LOG);
    assert_eq!(selected_after_meta_b, 7_733_248);

    let selected_main_start = align_up(selected_after_meta_b, 1 << SELECTED_MAIN_LOG);
    assert_eq!(selected_main_start, selected_after_meta_b);
    let selected_after_main =
        selected_main_start + SELECTED_MAIN_COLUMNS * (1 << SELECTED_MAIN_LOG);
    assert_eq!(selected_after_main, 8_126_464);

    // Same-domain ties follow logical family order: unchanged Meta-A before
    // selected Owner. This does not change the row total, but it pins one
    // canonical slice map and therefore one future matrix/VK identity.
    let selected_meta_a_start = align_up(selected_after_main, 1 << SELECTED_META_A_LOG);
    assert_eq!(selected_meta_a_start, selected_after_main);
    let selected_after_meta_a =
        selected_meta_a_start + SELECTED_META_A_COLUMNS * (1 << SELECTED_META_A_LOG);
    assert_eq!(selected_after_meta_a, 8_388_608);

    let selected_owner_start = align_up(selected_after_meta_a, 1 << SELECTED_OWNER_LOG);
    assert_eq!(selected_owner_start, selected_after_meta_a);
    let selected_after_columns =
        selected_owner_start + SELECTED_OWNER_COLUMNS * (1 << SELECTED_OWNER_LOG);
    assert_eq!(selected_after_columns, 8_585_216);

    let selected_after_meta_closure =
        selected_after_columns + B255_PAIRED_COPY_AND_GHOST_ROWS + B255_UNCHANGED_META_PIN_ROWS;
    assert_eq!(selected_after_meta_closure, 8_816_388);
    let selected_before_unchanged_tail =
        selected_after_meta_closure + selected_all_tiles_rows + SELECTED_PAD_MATERIALIZATION_ROWS;
    assert_eq!(selected_before_unchanged_tail, 11_950_088);
    let selected_replacement_target_rows = selected_before_unchanged_tail
        + B255_LEGACY_ACTION_ALLOCATOR_ROWS
        + B255_LEGACY_PAIRED_TOPOLOGY_ROWS
        + B255_LEGACY_STRUCTURAL_FRONTIER_ROWS
        + B255_LEGACY_ACCUMULATOR_AND_HEADER_ROWS
        + B255_BLOCK_IO_PIN_ROWS;
    assert_eq!(
        selected_replacement_target_rows,
        B255_SELECTED_REPLACEMENT_TARGET_ROWS
    );
    assert_eq!(
        B255_CURRENT_BLOCK_ROWS - selected_replacement_target_rows,
        591_608
    );
    assert!(selected_replacement_target_rows < B255_BLOCK_SCREENING_CEILING);
    assert!(selected_replacement_target_rows < M24_ROWS);
    let selected_screen_headroom = B255_BLOCK_SCREENING_CEILING - selected_replacement_target_rows;
    let selected_m24_headroom = M24_ROWS - selected_replacement_target_rows;

    println!("PARANOID authorization ZK-capsule geometry roofline");
    println!("  geometry screen; exact Block total is measurement-cross-checked");
    println!("  B255 auth slots                         {auth_slots:>10}");
    println!("  Wallet-A domain / w_log       {wallet_a_domain:>10} / 19");
    println!("  Wallet-B domain / w_log       {wallet_b_domain:>10} / 18");
    println!(
        "  source/mid path / stride             {}/{} / {}",
        g.source_path_depth, g.mid_path_depth, g.wallet_b_stride
    );
    println!(
        "  owner transcript exact model             {ZK_AUTH_OWNER_COMPILED_SLOTS:>3} / 128 slots"
    );
    println!(
        "  main transcript exact model              {ZK_AUTH_MAIN_COMPILED_SLOTS:>3} / 256 slots"
    );
    println!("  multiproof siblings source/mid        {source_siblings:>3} / {mid_siblings}");
    println!(
        "  modeled payload                     {candidate_payload_bytes:>7} / {PROOF_SIZE_TARGET_BYTES} bytes"
    );
    println!("  unassigned serialization headroom   {unassigned_serialization_headroom:>7} bytes");
    println!("  fixed upper/tail linkage delta       {upper_linkage_delta:>10}");
    println!("  raw isolated geometry delta          {raw_geometry_delta:>10}");
    println!("  aligned pre-Main-C delta              {aligned_geometry_delta:>10}");
    println!(
        "  safety row subtotal                 {aligned_static_rows:>10} / {B255_BLOCK_SCREENING_CEILING} screen"
    );
    println!("  Owner-C surviving credit (applied)    {owner_c_surviving_credit:>10}");
    println!("  Owner-C m16->m15 raw (unapplied)      {owner_c_column_raw_credit:>10}");
    println!("  rc-tensor aligned credit (unapplied)  {rc_tensor_aligned_credit:>10}");
    println!("  row-screen headroom                   {row_screen_headroom:>10}");
    println!("  raw m24 headroom                      {raw_m24_headroom:>10}");
    println!("\n  exact replacement integration ledger (MEASURED CROSS-CHECK)");
    println!("  measured legacy Block rows            {reconstructed_legacy_rows:>10}");
    println!("  retained action/public rows           {retained_public_arithmetic_rows:>10}");
    println!("  deleted legacy proof carrier rows     {removed_legacy_owner_carrier_rows:>10}");
    println!("  selected all-tiles rows               {selected_all_tiles_rows:>10}");
    println!("  PAD255 constant materialization       {SELECTED_PAD_MATERIALIZATION_ROWS:>10}");
    println!("  target complete Block rows            {selected_replacement_target_rows:>10}");
    println!("  target saving vs measured legacy      {:>10}", 591_608);
    println!("  target screening headroom             {selected_screen_headroom:>10}");
    println!("  target raw m24 headroom               {selected_m24_headroom:>10}");
}
