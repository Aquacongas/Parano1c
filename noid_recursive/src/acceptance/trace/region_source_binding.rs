// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! [G] — the COMPLETE wallet-capsule PCS opening AUTHENTICATION discharged
//! IN-TRACE via region families in ONE builder
//! ([`discharge_auth_pcs_obligation_via_region`]).
//!
//! Given the [`PendingAuthPcsObligation`] the owner-auth slot produced and
//! the native [`AuthMleOpeningProof`], this replays `capsule_verify` over
//! region columns: two capsule-leaf sponge families (the queried source and
//! mid cosets), two feed-forward Merkle legs (source paths to the committed
//! cap, mid paths to the FS-observed mid root), the per-query arity-16 fold
//! chain (source coset → mid cell → `Code(h)`), the two upper-contraction
//! dot checks, the pre-query grind check, and the FRICHANL transcript as a
//! duplex walk. It pins every reduction terminal inline and collects every
//! committed-column opening claim as a [`RegionPcsClaim`] for the CALLER to
//! thread through the link's public IO — this fn RETURNS them and does NOT
//! build the public IO / prove.
//!
//! ## Structure — THREE union walks in ONE builder (memory)
//! A single deep-chain walk is ~1M rows; one walk per family OOMs (region
//! prover memory note). The assembly uses exactly three union walks:
//!   - **walk A (leaf-union)**: the source + mid capsule-leaf tiles (and the
//!     exact-state sponge tiles + spine tree/tile when handed off) under ONE
//!     carry-selection + ONE walk + ONE unioned substitution; it opens each
//!     tile's digest cells to shared wires.
//!   - **walk B (merkle-union)**: the two feed-forward capsule legs plus the
//!     exact-state / tx-root 2-permutation legs, a heterogeneous union under
//!     ONE carry-selection + ONE walk + ONE unioned substitution (+ the
//!     CR-chain / direction zero-check relation).
//!   - **walk C (duplex-union)**: the K txs' FRICHANL channels.
//! Walk A's tile-digest wires feed walk B's leg entries (the ff legs' CR
//! start cells) — SHARED builder wires, never a public constant.
//!
//! ## Authentication-root TRANSCRIPT binding
//! Every leg's recomputed root is bound to the Fiat-Shamir-OBSERVED root
//! wire (absorbed BEFORE the query draw), so a prover cannot authenticate
//! fabricated answers against a root chosen after the query positions are
//! known:
//!   - the SOURCE leg's per-path root == the commitment cap lane selected by
//!     a witness-bit mux over the query's rate-coset bits (the cap was
//!     absorbed at the transcript start);
//!   - the MID leg's per-path root == the `mid_root` digest wires (absorbed
//!     before the grind + query draw).
//! The recomputed ff root is the LinExpr `C + CR + D·(CR + SIB)` at the last
//! node slot (every cell bound by the walk's random-point opening), pinned
//! == the observed wire — an R1CS row, not an IO claim, so the binding stays
//! flat in tx count. Query POSITIONS are bound exactly: each ff direction
//! cell is pinned to the corresponding transcript-derived query-position bit
//! and each leaf tile's meta cell to the bit-recomposed leaf index.
//!
//! ## Scope
//! Production params authenticate EVERY query (`nq = CAPSULE_NUM_QUERIES`)
//! on both trees. `RegionDischargeParams::nq` lets unit gates authenticate a
//! subset (the channel is still driven with the full count, so the
//! transcript stays faithful).

use noid_core::hardware::flat_to_tower_u128;
use noid_core::Block128;
use noid_fri::Channel;
use noid_fri_binius::capsule::{
    absorb_capsule_commitment, capsule_leaf_hash, capsule_leaf_of_position, capsule_tree_depth,
    CapsuleNodeHasher, CAPSULE_CAP_DEPTH, CAPSULE_GRIND_BITS, CAPSULE_LEAF_SYMBOLS,
    CAPSULE_LOG_RATE, CAPSULE_NUM_QUERIES, CAPSULE_RATE, CAPSULE_TAU, CAPSULE_WIDE_LOG,
};
use noid_fri_binius::compact_fri::{
    expand_batched_merkle_proof, expand_batched_merkle_proof_to_cap, BatchedMerkleProof,
};
use noid_gkr::auth_pcs::AuthMleOpeningProof;
use noid_gkr::owner_auth::{OwnerAuthProofKillShot, OwnerAuthPublicInputs, OWNER_AUTH_NUM_VARS};
use noid_poseidon2b::native::domain::{
    capacity_iv, DomainTag, TAG_EXSTNOD, TAG_FRICHANL, TAG_KSCHANNL,
};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::capsule_leaf::{
    build_capsule_leaf_columns, capsule_leaf_fixed_patterns, capsule_leaf_iv_flat, raw_flat_lane,
    CapsuleLeafData, CAPSULE_LEAF_DIGEST_SLOT, CAPSULE_LEAF_STRIDE,
};
use noid_ivc_core::deep_chain::ff_merkle::{
    build_ff_merkle_path_columns, ff_merkle_chain_terms, ff_merkle_fixed_patterns,
    ff_merkle_substitution_terms, FfMerkleFamilyRefs, FfMerklePathFamily, FfMerklePathWitness,
};
use noid_ivc_core::deep_chain::leaf_hash::{
    build_sponge_leaf_columns, slot_leaf_iv_flat, slot_leaf_pad_flat, sponge_leaf_fixed_patterns,
    sponge_leaf_substitution_terms, SpongeLeafRefs, SPONGE_LEAF_DIGEST_SLOT, SPONGE_LEAF_SLOTS,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2, ColRef,
    ColumnRelationProof, FixedPattern, RelationColumns, RelationTerm, ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::schedule::{
    build_duplex_columns, build_merkle_path_columns, carry_selection_terms, compile_duplex,
    duplex_family_refs, duplex_fixed_patterns, duplex_substitution_terms, flat_of_tower_u128,
    merkle_booleanity_terms, merkle_fixed_patterns, merkle_substitution_terms, DuplexFamilyRefs,
    DuplexLayout, DuplexSlot, LaneSource, MerkleFamilyRefs, MerklePathColumns, MerklePathFamily,
    MerklePathWitness,
};
use noid_ivc_core::deep_chain::source_tree::{
    compress_iv_flat, mds_weights_pub, source_tree_substitution_terms, SourceTreeRefs,
};
use noid_ivc_core::deep_chain::spine::{
    build_spine_instance_columns, spine_input_digest_slot, spine_output_digest_slot,
    spine_pad_absorb_flat, spine_tile_fixed_patterns, spine_tree_exposure_terms,
    spine_tree_fixed_patterns, spine_tree_internal_child_pattern, SpineInstanceFlat,
    SPINE_N_INPUT_LEAVES, SPINE_N_OUTPUT_LEAVES, SPINE_TILE_SLOTS, SPINE_TILE_WRAP_SLOT,
    SPINE_TREE_KID_LEAF_BASE, SPINE_TREE_SLOTS,
};
use noid_ivc_core::deep_chain::{
    prove_deep_chain_walk, verify_deep_chain_walk, DeepChainWalkProof, LaneClaimGroup,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{
    FieldR1csBuilder, FsChannelOps, FsChannelTrace, FsChannelUnionRecorder, LinExpr,
    RecordedChannel, Wire,
};
use noid_ivc_core::public_io::WitnessSlice;

use super::deep_chain::{
    verify_column_relation_trace, verify_deep_chain_walk_trace, verify_shift_discharge_trace,
    ColumnRelationProofTrace, DeepChainWalkProofTrace, LaneClaimGroupTrace, RelationTermTrace,
    ShiftDischargeProofTrace,
};
use super::exact_state::ExactStateRegionData;
use super::fri_pcs::{
    compact_queries_from_squeezes_with_bits, forward_ntt_trace, mle_evaluate_small_trace,
};
use super::owner_auth::{
    owner_boundary_constraints, owner_boundary_target, owner_boundary_w,
    owner_combined_target_trace, owner_shift_weights_at_point, owner_unified_final_evals,
    OwnerAuthProofTrace, OwnerAuthPublicInputsTrace, OwnerUnifiedReductionTrace,
    PendingAuthPcsObligation,
};
use super::{
    alloc_blocks, eq_ind_partial_eval_trace, eq_ind_trace, flat_of, mul, pin_eq, pin_zero,
    BatchEvalReductionTrace,
};
use crate::acceptance::region::{
    capsule_pcs_channel_schedule, owner_auth_channel_schedule, CAPSULE_OPEN_TAG,
};

// FS domains for the two region walks (self-contained sub-protocols; the
// soundness of the discharge lives in the committed-column opening claims the
// caller threads through the outer PCS, not in these transcripts).
const DOMAIN: &[u8] = b"source-binding-full-leaf-union";
const DOMAIN_B: &[u8] = b"source-binding-full-merkle-union";
const DOMAIN_C: &[u8] = b"source-binding-full-duplex-union";

// Meta committed column order (all length P):
//   KID0=0, KID1=1, IN0=2, IN1=3, C0=4..C3=7.
// The source-tree CODE lanes RIDE the IN columns: CODE cells live only in
// source-tree slots ([tx_off, +st_slots) and the ghosted spine trees), IN
// cells only in leaf/es/spine-tile slots — disjoint by layout, and every
// relation term reading either is gated by its family's fixed pattern.
const KID0: usize = 0;
const IN0: usize = 2;
const CODE0: usize = IN0;
const C0: usize = 4;
const N_COMMITTED: usize = 8;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One discharged committed-column opening claim, carrying both the trace-wire
/// (point, value) and the concrete native (point, value) the caller folds into
/// the link's public IO envelope. `slice` is the committed [`WitnessSlice`]
/// allocated in the builder for this claim's column.
pub struct RegionPcsClaim {
    pub slice: WitnessSlice,
    /// Trace-wire point coordinates.
    pub point: Vec<LinExpr>,
    /// Trace-wire opened value.
    pub value: LinExpr,
    /// Native point (for the caller's IO envelope).
    pub native_point: Vec<F128>,
    /// Native opened value (for the caller's IO envelope).
    pub native_value: F128,
}

/// The one documented memory reduction of the region discharge, exposed so
/// unit gates can keep it small while the link passes the full value.
#[derive(Clone, Copy, Debug)]
pub struct RegionDischargeParams {
    /// Number of queries AUTHENTICATED per tree (a subset of
    /// [`CAPSULE_NUM_QUERIES`]; the channel is still driven with the full
    /// count, so the transcript is faithful). Production =
    /// `CAPSULE_NUM_QUERIES` — every query authenticated on both trees.
    pub nq: usize,
}

/// Discharge one [`PendingAuthPcsObligation`] — the region twin of the inline
/// [`super::auth_pcs::discharge_auth_pcs_obligation`]. Thin wrapper over the
/// plural [`discharge_auth_pcs_obligations_via_region`] with a single tx.
pub fn discharge_auth_pcs_obligation_via_region(
    b: &mut FieldR1csBuilder,
    obligation: &PendingAuthPcsObligation,
    native: &AuthMleOpeningProof,
    params: RegionDischargeParams,
) -> Vec<RegionPcsClaim> {
    discharge_auth_pcs_obligations_via_region(
        b,
        std::slice::from_ref(obligation),
        std::slice::from_ref(native),
        params,
        None,
        None,
        None,
        None,
    )
}

/// Discharge K [`PendingAuthPcsObligation`]s (one per tx of a block) IN-TRACE in
/// ONE builder. Replays each wallet-capsule mixed opening over region families,
/// TRANSCRIPT-BINDS each Merkle-auth root to its FS-observed root wire, closes
/// each discharge contract (`all_openings[0] == reduction.value`), and RETURNS
/// every committed-column opening claim for the caller to thread through the
/// link's public IO. The K txs' families TILE into ONE walk A (source_tree +
/// leaves) + ONE walk B (merkle) at common-period offsets — the walk cost is
/// logarithmic in the tiled domain (transaction-count independent), K per-tree
/// exposures the only per-tx source-tree residual.
///
/// `es` (exact-state region handoff, [`ExactStateRegionData`]): when `Some`,
/// the block's exact-state hashing families ride the SAME walks — no new walk
/// is ever spawned. The `2T` slot-leaf sponge tiles join walk A as one more
/// leaf family (its plain `IN` reads gated by a region-ones pattern); the
/// state paths (TAG_EXSTNOD) join walk B as one more Merkle leg. Block-level entries are chunked
/// `ceil(len/K)` per tx block (contiguous, canonical-ghost-filled), so the
/// layout stays a deterministic function of (input lengths, K, depths) —
/// class-fixed. Leaf digests pin to the slot-leaf `expected_leaf` statement
/// wires which double as the state leg's entry wires (the leaf↔path closure),
/// and each root pins directly to the parent/grown-parent or child header wires.
///
/// `txr` (tx-root region handoff, [`TxRootRegionData`]): when `Some`, the
/// block's tx-root Merkle paths ride walk B as one more TAG_COMPRESS leg —
/// entries are the SPINE tx-hash wires, every root pins to the header
/// `tx_root` wires, the leaf POSITIONS are bound by const-pinning the
/// committed direction cells to the leaf-index bits, and the last real
/// path's right-hand sibling cells are const-pinned to the zero-subtree
/// padding constants (exactly the bindings the inline slot pinned on its
/// statement wires).
///
/// `spine` (tx-body spine region handoff, [`SpineRegionData`]): when `Some`,
/// every transaction's 59-permutation tx-body hash rides walk A as TWO more
/// families — the 32-slot leaf/wrap TILE (the 12 leaf sub-sponges + the wrap,
/// a region-gated sponge-shape family) and the 64-slot compress TREE (the
/// source-tree heap shape with a zero `LEAFODD` pattern and a GATED
/// internal-child exposure). Joins are cell pins: leaf payload statement
/// wires → tile `IN` cells (the input pad flush is a const pin), chain
/// digests → tile `C` cells AND tree KID leaf cells (shared wires), the
/// statement lanes (anchor / fee / coinbase / pad) → the remaining KID leaf
/// cells, the tree root → the wrap `IN` cells, and the wrap digest → the
/// `tx_hashes` statement wires (which the tx-root leg and the owner-auth
/// statements already consume). Instances are chunked `ceil(n/K)` per tx
/// block with canonical GHOST spines (the zero body) past the real count.
pub fn discharge_auth_pcs_obligations_via_region(
    b: &mut FieldR1csBuilder,
    obligations: &[PendingAuthPcsObligation],
    natives: &[AuthMleOpeningProof],
    params: RegionDischargeParams,
    es: Option<&ExactStateRegionData>,
    txr: Option<&TxRootRegionData>,
    spine: Option<&SpineRegionData>,
    oa_recording: Option<&RecordedChannel>,
) -> Vec<RegionPcsClaim> {
    assert_eq!(
        obligations.len(),
        natives.len(),
        "one native proof per obligation"
    );
    assert!(!obligations.is_empty(), "at least one obligation");
    // The K txs' families tile ONE walk A (source tree + leaves) + ONE walk B
    // (pair-leaf + merkle legs) + ONE walk C (FRICHANL channels) at common-period
    // offsets, with K per-tree source-tree exposures and a per-tx algebra loop.
    let k = obligations.len();
    let mut ledger = b.num_wires();

    // ===================================================================
    // Class-level shapes (identical across the block's txs; the class is
    // shape-fixed, so tx 0 defines the whole layout).
    // ===================================================================
    let num_vars = obligations[0].num_vars;
    let nq = params.nq;
    let log_n = natives[0].commitment.log_rows;
    assert_eq!(log_n, num_vars, "capsule commitment shape");
    assert!(num_vars > CAPSULE_TAU, "capsule column below the tau fold");
    assert!(
        nq <= CAPSULE_NUM_QUERIES,
        "nq exceeds the channel's query draw"
    );
    assert!(
        nq.is_power_of_two(),
        "nq must be a power of two (tile alignment)"
    );
    let low_vars = num_vars - CAPSULE_TAU;
    let low_len = 1usize << low_vars;
    let mid_log = num_vars - CAPSULE_WIDE_LOG;
    // Two capsule-leaf tile families (source + mid cosets), nq tiles each.
    let leaf_stride = CAPSULE_LEAF_STRIDE;
    let n_leaf_families = 2usize;
    let leaf_family_slots = nq * leaf_stride;

    // Walk-A domain: `[tx_hi | within-tx block]`. Every tx's two leaf-tile
    // families occupy one power-of-two block; the K blocks tile the domain,
    // so common-period patterns (period = the block) cover every tx.
    //
    // Exact-state extension: the block's `2T` slot-leaf sponge tiles ride the
    // SAME walk A after the wallet leaf families, distributed across the K tx
    // blocks in contiguous chunks of `es_leaf_cap = ceil(2T/K)` tiles each
    // (shortfall = canonical ghost sponge leaves) — the layout stays a pure
    // function of (2T, K).
    let es_leaf_base = n_leaf_families * leaf_family_slots; // within a tx block
    let es_leaf_cap = es.map_or(0, |e| e.leaves.len().div_ceil(k));
    let es_end = es_leaf_base + es_leaf_cap * SPONGE_LEAF_SLOTS;
    // Spine extension: `spine_cap = ceil(n_instances/K)` tree+tile pairs per tx
    // block, trees first. The tree run must start at a multiple of
    // `SPINE_TREE_SLOTS · spine_cap` so the gated exposure's window claims
    // re-point into walk A with constant offset bits (the same zero-bit
    // insertion trick as the wallet trees, plus the instance coordinates);
    // `spine_cap` must be a power of two for the instance bits to split.
    let spine_cap = spine.map_or(0, |s| s.instances.len().div_ceil(k));
    assert!(
        spine_cap == 0 || spine_cap.is_power_of_two(),
        "spine per-block capacity must be a power of two (got {spine_cap})"
    );
    let spine_tree_base = if spine_cap > 0 {
        es_end.next_multiple_of(SPINE_TREE_SLOTS * spine_cap)
    } else {
        es_end
    };
    let spine_tile_base = spine_tree_base + spine_cap * SPINE_TREE_SLOTS;
    let per_tx_a = spine_tile_base + spine_cap * SPINE_TILE_SLOTS;
    let block_log_a = per_tx_a.next_power_of_two().trailing_zeros() as usize;
    let per_tx_block_a = 1usize << block_log_a;
    let w_log = (k * per_tx_block_a).next_power_of_two().trailing_zeros() as usize;
    let p = 1usize << w_log;
    let leaf_base = |f: usize| f * leaf_family_slots; // within a tx block

    // Walk-B leg layout (class constant). The two wallet legs are
    // FEED-FORWARD (1 slot per node, stride = depth.next_pow2): the source
    // paths run to the committed cap (depth = tree − cap), the mid paths to
    // the root. The exact-state / tx-root legs stay on the 2-permutation
    // family (consensus trees are unchanged); their node capacity IV is a
    // per-leg pattern parameter, so heterogeneous tags coexist in ONE walk B.
    let ff_depths: [usize; 2] = [
        capsule_tree_depth(num_vars) - CAPSULE_CAP_DEPTH,
        capsule_tree_depth(mid_log),
    ];
    let ff_strides: [usize; 2] = std::array::from_fn(|f| ff_depths[f].next_power_of_two());
    let mut leg_depths: Vec<usize> = Vec::new();
    let mut leg_caps: Vec<usize> = Vec::new();
    let mut leg_ivs: Vec<[F128; 2]> = Vec::new();
    let es_state_leg = 0usize;
    if let Some(e) = es {
        leg_depths.push(e.d_state);
        leg_caps.push(e.paths.len().div_ceil(k));
        leg_ivs.push(iv_flat_of_tag(TAG_EXSTNOD));
    }
    // Tx-root paths: one TAG_COMPRESS leg, one path per user tx chunked
    // across the tx blocks.
    let txr_leg = leg_depths.len();
    if let Some(t) = txr {
        assert!(!t.paths.is_empty(), "tx-root region handoff without paths");
        leg_depths.push(t.depth);
        leg_caps.push(t.paths.len().div_ceil(k));
        leg_ivs.push(compress_iv_flat());
    }
    let n_legs = leg_depths.len();
    // Per-tx block: the two ff legs first, then the 2-perm legs.
    let mut ff_bases = [0usize; 2];
    let mut acc = 0usize;
    for f in 0..2 {
        ff_bases[f] = acc;
        acc += nq * ff_strides[f];
    }
    let mut meta_bases = Vec::with_capacity(n_legs);
    for f in 0..n_legs {
        meta_bases.push(acc);
        acc += leg_caps[f] * (2 * leg_depths[f]).next_power_of_two();
    }
    let per_tx_b = acc;
    let block_log_b = per_tx_b.next_power_of_two().trailing_zeros() as usize;
    let per_tx_block_b = 1usize << block_log_b;
    let w_log_b = (k * per_tx_block_b).next_power_of_two().trailing_zeros() as usize;
    let pb = 1usize << w_log_b;
    // Walk-B committed set is leg-count FLAT: the legs' slot ranges are
    // disjoint, every relation term is gated by a leg-specific fixed pattern
    // (zero outside its own slots), and the only cross-boundary shifted
    // reads (`c_sh` at start slots) are cancelled by the START/NODE
    // patterns — so ALL legs share ONE physical column set. Column order:
    // C0..C3 = [0..4), E0,E1 = [4..6) (the ff legs' CR carried-digest lanes
    // RIDE the E columns), SIB0,SIB1 = [6..8), D = 8 — 9 columns regardless
    // of leg count.
    let n_committed_b = 9;
    let cb_c: [usize; STATE_SIZE] = std::array::from_fn(|i| i);
    let iv_capsnode = {
        let iv = noid_poseidon2b::native::domain::capacity_iv_flat(
            noid_poseidon2b::native::domain::TAG_CAPSNODE,
        );
        [raw_flat_lane(iv[0]), raw_flat_lane(iv[1])]
    };

    // ===================================================================
    // Shared columns (K-wide), ghost-filled once with perm([0;4]).
    // ===================================================================
    let mut cols: Vec<Vec<F128>> = (0..N_COMMITTED).map(|_| vec![F128::ZERO; p]).collect();
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let (ghost_s0, ghost_out) =
        noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..p {
        for j in 0..STATE_SIZE {
            s0[j][slot] = ghost_s0[j];
            s_out[j][slot] = ghost_out[j];
            cols[C0 + j][slot] = ghost_out[j];
        }
    }
    let mut cb: Vec<Vec<F128>> = (0..n_committed_b).map(|_| vec![F128::ZERO; pb]).collect();
    let mut s0b: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let mut soutb: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let (ghb0, ghbo) = noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..pb {
        for j in 0..STATE_SIZE {
            s0b[j][slot] = ghb0[j];
            soutb[j][slot] = ghbo[j];
            cb[j][slot] = ghbo[j];
        }
    }

    // ===================================================================
    // Accumulators filled by the per-tx loop, assembled after it.
    // ===================================================================
    let mut claims: Vec<Claim> = Vec::new(); // walk-A/B/C discharge openings (IO)
                                             // Stage 2: per-cell reads/pins (grand pins, symbols, digests, fold-join) are
                                             // R1CS constraints, NOT IO opening claims -- the columns are opened by the
                                             // walk discharges (random point), so every cell is bound. Collected as
                                             // (col, slot, wire) and resolved post-loop as pin_eq(wire, cell). Walk-A cols
                                             // resolve against `slices`; walk-B (fold-join) against `slices[n_slices_a+col]`.
    let mut cell_pins_a: Vec<(usize, usize, LinExpr)> = Vec::new();
    let mut cell_pins_b: Vec<(usize, usize, LinExpr)> = Vec::new();
    // Walk-A tiling requires a power-of-two obligation count so the tiled tx
    // bits align with walk-A's (the discharge pads a tier's real txs to
    // next_pow2 with ghost obligations).
    assert!(
        k.is_power_of_two(),
        "wallet-PCS region discharge expects a power-of-two obligation count \
         (pad the tier's real txs with ghost obligations); got {k}"
    );
    // Tiled SPINE-tree exposure: every instance (real + ghost, block-major)
    // appends its KID low half (2L cells) and full C (4L cells); ONE gated
    // sumcheck after the loop discharges every spine tree, re-pointing 4
    // terminal claims into walk A — flat (O(1)) in tx count.
    let mut spine_expo_kid0: Vec<F128> = Vec::new();
    let mut spine_expo_kid1: Vec<F128> = Vec::new();
    let mut spine_expo_c0: Vec<F128> = Vec::new();
    let mut spine_expo_c1: Vec<F128> = Vec::new();
    // Per-leg-type walk-B accumulators (each grows to K·cap across the loop).
    let mut acc_committed_roots: Vec<Vec<[F128; 2]>> = vec![Vec::new(); n_legs];
    let mut acc_recomputed_roots: Vec<Vec<[F128; 2]>> = vec![Vec::new(); n_legs];
    let mut acc_entry_wires: Vec<Vec<[LinExpr; 2]>> = vec![Vec::new(); n_legs];
    let mut acc_root_wires: Vec<Vec<[LinExpr; 2]>> = vec![Vec::new(); n_legs];
    let mut acc_path_slots: Vec<Vec<usize>> = vec![Vec::new(); n_legs];
    // Feed-forward wallet legs: entry pins go through `cell_pins_b` (CR
    // start cells); root pins are COMPOSITE (`C + CR + D·(CR+SIB)` at the
    // last node slot == the FS-observed root wire), collected here and
    // resolved once the walk-B slices exist.
    let mut ff_root_pins: Vec<(usize, [LinExpr; 2])> = Vec::new();
    let mut all_expands_ok = true;

    // -------------------------------------------------------------------
    // Walk C (the FRICHANL channel union) class-level setup. The channel op
    // schedule is class-fixed (a function of the shape, not the proof values),
    // so tx 0 defines the layout, domain, IV, and per-tx query counts; each tx
    // fills its own duplex columns + challenge/absorb wires in the loop.
    // -------------------------------------------------------------------
    let point0: Vec<Block128> = obligations[0]
        .reduction
        .point
        .iter()
        .map(|e| {
            let f = e.eval(b.values());
            Block128::from(flat_to_tower_u128((f.lo as u128) | ((f.hi as u128) << 64)))
        })
        .collect();
    let chan_layout =
        compile_duplex(&capsule_pcs_channel_schedule(&natives[0], num_vars, &point0).ops);
    let chan_data_positions = duplex_data_positions(&chan_layout);
    let per_tx_block_c = chan_layout.slots.len().next_power_of_two();
    let block_log_c = per_tx_block_c.trailing_zeros() as usize;
    let iv_c = {
        let iv = capacity_iv(TAG_FRICHANL);
        [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
    };
    let mut chan_data_streams: Vec<Vec<F128>> = Vec::with_capacity(k);
    let mut chan_chal_wires: Vec<Vec<LinExpr>> = Vec::with_capacity(k);
    let mut chan_data_wires: Vec<Vec<LinExpr>> = Vec::with_capacity(k);

    for tx in 0..k {
        let obligation = &obligations[tx];
        let native = &natives[tx];
        let tx_off_a = tx * per_tx_block_a;
        let tx_off_b = tx * per_tx_block_b;
        // Shape checks (same contract as the native verifier).
        assert_eq!(native.commitment.log_rows, num_vars);
        assert_eq!(obligation.reduction.point.len(), num_vars);
        assert_eq!(
            obligation.commitment_cap_lanes.len(),
            native.commitment.cap.hashes.len()
        );
        assert_eq!(
            obligation.commitment_cap_lanes.len(),
            1usize << CAPSULE_CAP_DEPTH
        );
        let opening = &native.opening;
        assert_eq!(opening.upper_partial_evals.len(), 1usize << CAPSULE_TAU);
        assert_eq!(opening.h_evals.len(), low_len);
        assert_eq!(
            opening.source_symbols.len(),
            CAPSULE_NUM_QUERIES * CAPSULE_LEAF_SYMBOLS
        );
        assert_eq!(
            opening.mid_symbols.len(),
            CAPSULE_NUM_QUERIES * CAPSULE_LEAF_SYMBOLS
        );

        // Recover the NATIVE reduction point (tower) from the obligation wires.
        let point: Vec<Block128> = obligation
            .reduction
            .point
            .iter()
            .map(|e| {
                let f = e.eval(b.values());
                Block128::from(flat_to_tower_u128((f.lo as u128) | ((f.hi as u128) << 64)))
            })
            .collect();
        let point_w = &obligation.reduction.point;

        // ---------------------------------------------------------------
        // Walk-C channel: this tx's class-fixed schedule + concrete duplex
        // columns. The squeezed-challenge wires feed the per-tx algebra; the
        // absorbed-data wires (schedule order) bind to the walk-C A-lane
        // cells after the loop. No inline channel replay.
        // ---------------------------------------------------------------
        let value_w = alloc_blocks(b, std::slice::from_ref(&opening.value))[0].clone();
        let upper = alloc_blocks(b, &opening.upper_partial_evals);
        let h_evals_w = alloc_blocks(b, &opening.h_evals);
        let mid_root_w = alloc_digest_raw(b, &opening.mid_root);
        let nonce_block = Block128::from(opening.grind_nonce as u128);
        let nonce_w = alloc_blocks(b, std::slice::from_ref(&nonce_block))[0].clone();

        // Challenges in schedule order: [beta x tau, grind, query x N].
        let schedule = capsule_pcs_channel_schedule(native, num_vars, &point);
        let dcols = build_duplex_columns(&chan_layout, iv_c, &schedule.data_flat, block_log_c);
        let chal_w: Vec<LinExpr> = dcols
            .challenges
            .iter()
            .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
            .collect();
        assert_eq!(
            chal_w.len(),
            CAPSULE_TAU + 1 + CAPSULE_NUM_QUERIES,
            "channel challenge count"
        );
        let beta: Vec<LinExpr> = chal_w[..CAPSULE_TAU].to_vec();
        let grind_chal = chal_w[CAPSULE_TAU].clone();
        let query_sq: Vec<LinExpr> = chal_w[CAPSULE_TAU + 1..].to_vec();

        // Absorbed-data wires in schedule order (MUST mirror
        // `capsule_pcs_channel_schedule`; the eval assert is the safety net
        // against any lane-convention or ordering drift).
        let mut data_wires: Vec<LinExpr> = Vec::with_capacity(schedule.data_flat.len());
        for lane in &obligation.commitment_cap_lanes {
            data_wires.push(lane[0].clone());
            data_wires.push(lane[1].clone());
        }
        data_wires.push(value_w.clone());
        for w in point_w.iter() {
            data_wires.push(w.clone());
        }
        for w in &upper {
            data_wires.push(w.clone());
        }
        data_wires.push(mid_root_w[0].clone());
        data_wires.push(mid_root_w[1].clone());
        for w in &h_evals_w {
            data_wires.push(w.clone());
        }
        data_wires.push(nonce_w.clone());
        assert_eq!(
            data_wires.len(),
            schedule.data_flat.len(),
            "absorb data lane count"
        );
        for (kk, w) in data_wires.iter().enumerate() {
            assert_eq!(
                w.eval(b.values()),
                schedule.data_flat[kk],
                "absorb data wire {kk}"
            );
        }
        chan_data_streams.push(schedule.data_flat.clone());
        chan_chal_wires.push(chal_w);
        chan_data_wires.push(data_wires);

        // Grind: the squeeze after the nonce absorb ends in
        // CAPSULE_GRIND_BITS zero bits. The bits are the tower decomposition
        // of the squeezed challenge (the native rule masks the tower value),
        // and their phi-weighted sum is zero iff every bit is zero.
        {
            let (_, gbits) = compact_queries_from_squeezes_with_bits(
                b,
                std::slice::from_ref(&grind_chal),
                CAPSULE_GRIND_BITS as usize,
            );
            let mut low = LinExpr::zero();
            for (i, bit) in gbits[0].iter().enumerate() {
                low = low.add(&bit.scale(flat_of(Block128::from(1u128 << i))));
            }
            pin_zero(b, &low);
        }

        // Query positions over nv + CAPSULE_LOG_RATE bits, from the walk-C
        // carry-cell squeezes; cross-checked against the REAL channel.
        let (query_indices, query_bits) =
            compact_queries_from_squeezes_with_bits(b, &query_sq, num_vars + CAPSULE_LOG_RATE);
        assert!(query_indices.len() >= nq, "need at least nq queries");
        let native_queries = derive_queries(native, &point);
        assert_eq!(query_indices, native_queries, "walk-C queries match native");

        // ---------------------------------------------------------------
        // Claim checks: (1) the upper contraction reproduces the value at
        // x_top; (2) it reproduces h(x_low) at beta (the Schwartz-Zippel
        // binding of the low contraction). Then the discharge contract: the
        // opened value == the owner-auth reduction value.
        // ---------------------------------------------------------------
        let (x_low_w, x_top_w) = point_w.split_at(low_vars);
        let eq_top = eq_ind_partial_eval_trace(b, x_top_w);
        let mut derived = LinExpr::zero();
        for (e, u) in eq_top.iter().zip(upper.iter()) {
            derived = derived.add(&mul(b, e, u));
        }
        pin_eq(b, &derived, &value_w);
        let eq_beta = eq_ind_partial_eval_trace(b, &beta);
        let mut batched = LinExpr::zero();
        for (e, u) in eq_beta.iter().zip(upper.iter()) {
            batched = batched.add(&mul(b, e, u));
        }
        let h_at_xlow = mle_evaluate_small_trace(b, &h_evals_w, x_low_w);
        pin_eq(b, &batched, &h_at_xlow);
        pin_eq(b, &value_w, &obligation.reduction.value);

        // Code(h) in-trace: the capsule-rate encode of the ABSORBED h table
        // (pure linear algebra, 0 constraints). The queried cell is read
        // through a witness-bit mux at the fold closure below.
        let code_h_w = capsule_encode_trace(&h_evals_w);

        // ---------------------------------------------------------------
        // Native per-query bookkeeping: leaf indices/hashes for BOTH trees
        // (over the full channel draw — the batched expands need every
        // queried leaf), and the expanded per-path authentication data.
        // ---------------------------------------------------------------
        let source_leaves_idx: Vec<usize> = native_queries
            .iter()
            .map(|&q| capsule_leaf_of_position(num_vars, q).0)
            .collect();
        let source_leaf_hashes: Vec<[u8; 32]> = (0..CAPSULE_NUM_QUERIES)
            .map(|q| {
                let syms = &opening.source_symbols
                    [q * CAPSULE_LEAF_SYMBOLS..(q + 1) * CAPSULE_LEAF_SYMBOLS];
                capsule_leaf_hash(num_vars, source_leaves_idx[q], syms)
            })
            .collect();
        let src_batch = BatchedMerkleProof {
            siblings: opening.source_batch.siblings.clone(),
        };
        let src_paths = expand_batched_merkle_proof_to_cap(
            &src_batch,
            capsule_tree_depth(num_vars),
            CAPSULE_CAP_DEPTH,
            &source_leaves_idx,
            &source_leaf_hashes,
            &CapsuleNodeHasher,
        )
        .expect("source octopus expand");
        all_expands_ok &= !src_paths.is_empty();
        let mid_leaves_idx: Vec<usize> = source_leaves_idx
            .iter()
            .map(|&leaf| capsule_leaf_of_position(mid_log, leaf).0)
            .collect();
        let mid_leaf_hashes: Vec<[u8; 32]> = (0..CAPSULE_NUM_QUERIES)
            .map(|q| {
                let syms =
                    &opening.mid_symbols[q * CAPSULE_LEAF_SYMBOLS..(q + 1) * CAPSULE_LEAF_SYMBOLS];
                capsule_leaf_hash(mid_log, mid_leaves_idx[q], syms)
            })
            .collect();
        let mid_batch = BatchedMerkleProof {
            siblings: opening.mid_batch.siblings.clone(),
        };
        let mid_paths = expand_batched_merkle_proof(
            &mid_batch,
            capsule_tree_depth(mid_log),
            &mid_leaves_idx,
            &mid_leaf_hashes,
            &CapsuleNodeHasher,
        )
        .expect("mid octopus expand");
        all_expands_ok &= !mid_paths.is_empty();

        // ---------------------------------------------------------------
        // Walk A: the source (family 0) and mid (family 1) capsule-leaf
        // tiles, nq tiles each, at this tx's block.
        // ---------------------------------------------------------------
        let mut fam_digest_vals: [Vec<[F128; 2]>; 2] = [Vec::new(), Vec::new()];
        for fam in 0..2 {
            let (msg_log, symbols, leaves_idx) = if fam == 0 {
                (num_vars, &opening.source_symbols, &source_leaves_idx)
            } else {
                (mid_log, &opening.mid_symbols, &mid_leaves_idx)
            };
            let tiles: Vec<CapsuleLeafData> = (0..nq)
                .map(|q| CapsuleLeafData {
                    msg_log,
                    leaf_index: leaves_idx[q],
                    syms: std::array::from_fn(|s| phi(symbols[q * CAPSULE_LEAF_SYMBOLS + s])),
                })
                .collect();
            let fam_wlog = (nq * leaf_stride).trailing_zeros() as usize;
            let (tc, digests) = build_capsule_leaf_columns(&tiles, fam_wlog);
            let base = tx_off_a + leaf_base(fam);
            let n_copy = nq * leaf_stride;
            for j in 0..2 {
                cols[IN0 + j][base..base + n_copy].copy_from_slice(&tc.in_[j][..n_copy]);
            }
            for j in 0..STATE_SIZE {
                cols[C0 + j][base..base + n_copy].copy_from_slice(&tc.c[j][..n_copy]);
                s0[j][base..base + n_copy].copy_from_slice(&tc.s0[j][..n_copy]);
                s_out[j][base..base + n_copy].copy_from_slice(&tc.s_out[j][..n_copy]);
            }
            fam_digest_vals[fam] = digests;
        }

        // ---------------------------------------------------------------
        // Per-query algebra + bindings: meta/symbol/digest cell pins, the
        // rc eq tensor (shared by fold twiddles and the cap-lane root mux),
        // the two arity-16 folds, and the ff-leg witnesses/pins.
        // ---------------------------------------------------------------
        let depth_s = ff_depths[0];
        let depth_m = ff_depths[1];
        let wide_hi: Vec<LinExpr> = (0..CAPSULE_WIDE_LOG)
            .map(|t| beta[CAPSULE_TAU - 1 - t].clone())
            .collect();
        let wide_lo: Vec<LinExpr> = (0..CAPSULE_WIDE_LOG)
            .map(|t| beta[CAPSULE_WIDE_LOG - 1 - t].clone())
            .collect();
        let cap_lanes: [Vec<LinExpr>; 2] = [
            obligation
                .commitment_cap_lanes
                .iter()
                .map(|l| l[0].clone())
                .collect(),
            obligation
                .commitment_cap_lanes
                .iter()
                .map(|l| l[1].clone())
                .collect(),
        ];
        let mut src_witnesses: Vec<FfMerklePathWitness> = Vec::with_capacity(nq);
        let mut mid_witnesses: Vec<FfMerklePathWitness> = Vec::with_capacity(nq);
        for q in 0..nq {
            let bits = &query_bits[q];
            let rc_bits = &bits[num_vars..num_vars + CAPSULE_LOG_RATE];
            // Leaf-index bits are [low local bits | rc bits] — the coset
            // member bits are excised from the middle of the position.
            let src_leaf_bits: Vec<LinExpr> = bits[..num_vars - CAPSULE_WIDE_LOG]
                .iter()
                .chain(rc_bits.iter())
                .cloned()
                .collect();
            let mid_leaf_bits: Vec<LinExpr> = bits[..num_vars - 2 * CAPSULE_WIDE_LOG]
                .iter()
                .chain(rc_bits.iter())
                .cloned()
                .collect();
            let mid_member_bits =
                &bits[num_vars - 2 * CAPSULE_WIDE_LOG..num_vars - CAPSULE_WIDE_LOG];

            // Meta-cell pins for both tiles: msg_log is a class constant;
            // leaf_index is the bit-recomposed query leaf (a raw flat lane,
            // linear in the transcript-bound bits).
            let src_tile = tx_off_a + leaf_base(0) + q * leaf_stride;
            let mid_tile = tx_off_a + leaf_base(1) + q * leaf_stride;
            cell_pins_a.push((
                IN0,
                src_tile,
                LinExpr::constant(raw_flat_lane(num_vars as u128)),
            ));
            cell_pins_a.push((IN0 + 1, src_tile, raw_lane_from_bits(&src_leaf_bits)));
            cell_pins_a.push((
                IN0,
                mid_tile,
                LinExpr::constant(raw_flat_lane(mid_log as u128)),
            ));
            cell_pins_a.push((IN0 + 1, mid_tile, raw_lane_from_bits(&mid_leaf_bits)));

            // Symbol wires pinned into the tile IN cells (slots 1..=8).
            let mut src_syms_w: Vec<LinExpr> = Vec::with_capacity(CAPSULE_LEAF_SYMBOLS);
            let mut mid_syms_w: Vec<LinExpr> = Vec::with_capacity(CAPSULE_LEAF_SYMBOLS);
            for s in 0..CAPSULE_LEAF_SYMBOLS {
                let sv = phi(opening.source_symbols[q * CAPSULE_LEAF_SYMBOLS + s]);
                let w = LinExpr::from_wire(b.alloc_f128(sv));
                cell_pins_a.push((IN0 + (s & 1), src_tile + 1 + s / 2, w.clone()));
                src_syms_w.push(w);
                let mv = phi(opening.mid_symbols[q * CAPSULE_LEAF_SYMBOLS + s]);
                let w = LinExpr::from_wire(b.alloc_f128(mv));
                cell_pins_a.push((IN0 + (s & 1), mid_tile + 1 + s / 2, w.clone()));
                mid_syms_w.push(w);
            }

            // rc eq tensor (2^CAPSULE_LOG_RATE lanes, LSB-first bits).
            let rc_tensor = bit_eq_tensor(b, rc_bits);

            // Fold chain: fold16(source coset) hits the mid coset member;
            // fold16(mid coset) hits the recomputed Code(h) cell.
            let folded = capsule_fold16_trace(b, &wide_hi, &rc_tensor, num_vars, &src_syms_w);
            let sel_mid = select_by_bits(b, mid_member_bits, &mid_syms_w);
            pin_eq(b, &folded, &sel_mid);
            let folded2 = capsule_fold16_trace(b, &wide_lo, &rc_tensor, mid_log, &mid_syms_w);
            let sel_code = select_by_bits(b, &mid_leaf_bits, &code_h_w);
            pin_eq(b, &folded2, &sel_code);

            // Tile digest wires (walk-A C cells) — the ff legs' entries.
            let mut src_entry = [LinExpr::zero(), LinExpr::zero()];
            let mut mid_entry = [LinExpr::zero(), LinExpr::zero()];
            for lane in 0..2 {
                let v = LinExpr::from_wire(b.alloc_f128(fam_digest_vals[0][q][lane]));
                cell_pins_a.push((C0 + lane, src_tile + CAPSULE_LEAF_DIGEST_SLOT, v.clone()));
                src_entry[lane] = v;
                let v = LinExpr::from_wire(b.alloc_f128(fam_digest_vals[1][q][lane]));
                cell_pins_a.push((C0 + lane, mid_tile + CAPSULE_LEAF_DIGEST_SLOT, v.clone()));
                mid_entry[lane] = v;
            }

            // ff leg S (source → cap): entry = the tile digest wires pinned
            // into CR(start); directions = the leaf-index bits pinned into
            // the D cells; root = the cap lane muxed by the rc bits
            // (TRANSCRIPT-BINDING — the cap was absorbed at the start).
            let src_path = src_paths
                .iter()
                .find(|pth| pth.leaf_index == source_leaves_idx[q])
                .expect("source path");
            assert_eq!(
                lanes_raw(&src_path.leaf_hash),
                fam_digest_vals[0][q],
                "source tile digest != native leaf"
            );
            let s_slot = tx_off_b + ff_bases[0] + q * ff_strides[0];
            src_witnesses.push(FfMerklePathWitness {
                entry: fam_digest_vals[0][q],
                siblings: src_path.siblings.iter().map(lanes_raw).collect(),
                directions: (0..depth_s)
                    .map(|kk| (source_leaves_idx[q] >> kk) & 1 == 1)
                    .collect(),
            });
            for lane in 0..2 {
                cell_pins_b.push((4 + lane, s_slot, src_entry[lane].clone()));
            }
            for (kk, bit) in src_leaf_bits.iter().enumerate().take(depth_s) {
                cell_pins_b.push((8, s_slot + kk, bit.clone()));
            }
            let mut cap_root = [LinExpr::zero(), LinExpr::zero()];
            for (c, t) in rc_tensor.iter().enumerate() {
                for lane in 0..2 {
                    cap_root[lane] = cap_root[lane].add(&mul(b, t, &cap_lanes[lane][c]));
                }
            }
            ff_root_pins.push((s_slot + depth_s - 1, cap_root));

            // ff leg M (mid → root): root = the FS-observed mid_root wires
            // (absorbed BEFORE the grind + query draw).
            let mid_path = mid_paths
                .iter()
                .find(|pth| pth.leaf_index == mid_leaves_idx[q])
                .expect("mid path");
            assert_eq!(
                lanes_raw(&mid_path.leaf_hash),
                fam_digest_vals[1][q],
                "mid tile digest != native leaf"
            );
            let m_slot = tx_off_b + ff_bases[1] + q * ff_strides[1];
            mid_witnesses.push(FfMerklePathWitness {
                entry: fam_digest_vals[1][q],
                siblings: mid_path.siblings.iter().map(lanes_raw).collect(),
                directions: (0..depth_m)
                    .map(|kk| (mid_leaves_idx[q] >> kk) & 1 == 1)
                    .collect(),
            });
            for lane in 0..2 {
                cell_pins_b.push((4 + lane, m_slot, mid_entry[lane].clone()));
            }
            for (kk, bit) in mid_leaf_bits.iter().enumerate().take(depth_m) {
                cell_pins_b.push((8, m_slot + kk, bit.clone()));
            }
            ff_root_pins.push((
                m_slot + depth_m - 1,
                [mid_root_w[0].clone(), mid_root_w[1].clone()],
            ));
        }

        // Build + place the two ff legs' columns; assert the recomputed
        // roots equal the committed roots (native path-replay consistency).
        for (fam, wits) in [(0usize, &src_witnesses), (1usize, &mid_witnesses)] {
            let family = FfMerklePathFamily {
                depth: ff_depths[fam],
                n_paths: nq,
            };
            let fam_wlog = (nq * ff_strides[fam]).trailing_zeros() as usize;
            let fcols = build_ff_merkle_path_columns(&family, iv_capsnode, wits, fam_wlog);
            place_ff(
                &mut cb,
                &mut s0b,
                &mut soutb,
                &fcols,
                tx_off_b + ff_bases[fam],
                nq * ff_strides[fam],
            );
            for q in 0..nq {
                let committed = if fam == 0 {
                    lanes_raw(&native.commitment.cap.hashes[source_leaves_idx[q] >> depth_s])
                } else {
                    lanes_raw(&opening.mid_root)
                };
                assert_eq!(fcols.roots[q], committed, "ff leg root != committed root");
            }
        }
    } // end `for tx in 0..k`
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: per-tx algebra loop");

    // ===================================================================
    // Exact-state families (block-level, chunked across the K tx blocks —
    // NEVER a new walk): the 2T slot-leaf sponge tiles fill walk A's es
    // region; the state Merkle paths fill walk B's exact-state leg. Chunk i
    // gets entries [i·cap, min((i+1)·cap, len)); the shortfall is canonical
    // ghosts, so every pattern-covered slot is a valid chain and the pin
    // structure is a pure function of (input lengths, K, depths).
    // ===================================================================
    if let Some(e) = es {
        let n_es = e.leaves.len();
        assert_eq!(e.paths.len(), n_es, "one state path per slot leaf");
        let pad_flat = slot_leaf_pad_flat();
        let state_cap = leg_caps[es_state_leg];
        for blk in 0..k {
            let lo = (blk * es_leaf_cap).min(n_es);
            let hi = ((blk + 1) * es_leaf_cap).min(n_es);

            // --- Walk A: this block's sponge-leaf tiles (chunk + ghosts). ---
            let chunk: Vec<(F128, F128, F128)> = e.leaves[lo..hi]
                .iter()
                .map(|l| (l.packed_value_flat, l.owner_hi_flat, l.owner_lo_flat))
                .collect();
            let tile_wlog = (es_leaf_cap * SPONGE_LEAF_SLOTS)
                .next_power_of_two()
                .trailing_zeros() as usize;
            let (tc, tile_digests) = build_sponge_leaf_columns(&chunk, tile_wlog);
            let base = blk * per_tx_block_a + es_leaf_base;
            let n_copy = es_leaf_cap * SPONGE_LEAF_SLOTS;
            for j in 0..2 {
                cols[IN0 + j][base..base + n_copy].copy_from_slice(&tc.in_[j][..n_copy]);
            }
            for j in 0..STATE_SIZE {
                cols[C0 + j][base..base + n_copy].copy_from_slice(&tc.c[j][..n_copy]);
                s0[j][base..base + n_copy].copy_from_slice(&tc.s0[j][..n_copy]);
                s_out[j][base..base + n_copy].copy_from_slice(&tc.s_out[j][..n_copy]);
            }
            for (t, g) in (lo..hi).enumerate() {
                let leaf = &e.leaves[g];
                assert_eq!(
                    tile_digests[t], leaf.expected_leaf_flat,
                    "es sponge tile digest != the statement's expected leaf"
                );
                let off = base + t * SPONGE_LEAF_SLOTS;
                // Statement wires pinned to the committed absorb cells; the
                // PAD lane is a protocol constant (`pad_after_one_field`).
                cell_pins_a.push((IN0, off, leaf.packed_value_w.clone()));
                cell_pins_a.push((IN0 + 1, off, leaf.owner_hi_w.clone()));
                cell_pins_a.push((IN0, off + 1, leaf.owner_lo_w.clone()));
                cell_pins_a.push((IN0 + 1, off + 1, LinExpr::constant(pad_flat)));
                // Digest cells == the expected-leaf statement wires — the
                // SAME wires the state leg reads as its Merkle entries (the
                // exact-state leaf↔path closure).
                let dslot = off + SPONGE_LEAF_DIGEST_SLOT;
                cell_pins_a.push((C0, dslot, leaf.expected_leaf_w[0].clone()));
                cell_pins_a.push((C0 + 1, dslot, leaf.expected_leaf_w[1].clone()));
            }

            // --- Walk B: this block's state-path chunk (the same chunking;
            // entries = the paired slot-leaf digest wires, roots = the
            // old/new expected-root statement wires). ---
            let state_paths: Vec<EsPathReal> = (lo..hi)
                .map(|g| {
                    let path = &e.paths[g];
                    assert_eq!(
                        path.entry_leaf_index, g,
                        "leaf↔path pairing is index-aligned"
                    );
                    assert_eq!(path.siblings.len(), e.d_state, "state path depth");
                    let leaf = &e.leaves[g];
                    let (root_w, root_flat) = if path.is_old {
                        (e.old_root_w.clone(), e.old_root_flat)
                    } else {
                        (e.new_root_w.clone(), e.new_root_flat)
                    };
                    EsPathReal {
                        entry_flat: leaf.expected_leaf_flat,
                        entry_w: leaf.expected_leaf_w.clone(),
                        siblings: path.siblings.clone(),
                        directions: path.directions.clone(),
                        root_flat,
                        root_w,
                    }
                })
                .collect();
            fill_es_merkle_leg(
                &mut cb,
                &mut s0b,
                &mut soutb,
                &mut acc_entry_wires[es_state_leg],
                &mut acc_root_wires[es_state_leg],
                &mut acc_committed_roots[es_state_leg],
                &mut acc_path_slots[es_state_leg],
                &mut acc_recomputed_roots[es_state_leg],
                e.d_state,
                state_cap,
                leg_ivs[es_state_leg],
                4,
                blk * per_tx_block_b + meta_bases[es_state_leg],
                &state_paths,
            );
        }
    }

    // ===================================================================
    // Tx-root paths (block-level, chunked like the exact-state families):
    // one TAG_COMPRESS walk-B leg, entries = the spine tx-hash wires, every
    // root = the underlying universal-tree Merkle root M wires. The leaf POSITION is bound by
    // const-pinning the committed direction cells to the leaf-index bits
    // (block content never moves a tx to another slot), and the padding rim
    // by const-pinning the LAST real path's right-hand sibling cells to the
    // zero-subtree constants — the exact bindings the inline slot pinned on
    // its statement wires. Const pins are self-testing: a wrong bit or rim
    // constant makes the HONEST witness unsatisfiable.
    // ===================================================================
    if let Some(t) = txr {
        let cap = leg_caps[txr_leg];
        let stride = (2 * t.depth).next_power_of_two();
        let d_col = 8;
        let sib_cols = [6, 7];
        let n_paths = t.paths.len();
        // Tier-capacity handoffs authenticate EVERY padded-tree leaf and carry
        // no rim constants (the padding leaves are proven zero directly);
        // exact-count handoffs carry one rim constant per level for the last
        // real path's right-hand siblings.
        assert!(
            t.rim_flat.is_empty() || t.rim_flat.len() == t.depth,
            "one rim constant per level (or none at tier capacity)"
        );
        for blk in 0..k {
            let lo = (blk * cap).min(n_paths);
            let hi = ((blk + 1) * cap).min(n_paths);
            let real: Vec<EsPathReal> = (lo..hi)
                .map(|j| {
                    let p = &t.paths[j];
                    assert_eq!(p.siblings.len(), t.depth, "tx-root path depth");
                    EsPathReal {
                        entry_flat: p.entry_flat,
                        entry_w: p.entry_w.clone(),
                        siblings: p.siblings.clone(),
                        directions: (0..t.depth).map(|l| (j >> l) & 1 == 1).collect(),
                        root_flat: t.root_flat,
                        root_w: t.root_w.clone(),
                    }
                })
                .collect();
            let region_base = blk * per_tx_block_b + meta_bases[txr_leg];
            fill_es_merkle_leg(
                &mut cb,
                &mut s0b,
                &mut soutb,
                &mut acc_entry_wires[txr_leg],
                &mut acc_root_wires[txr_leg],
                &mut acc_committed_roots[txr_leg],
                &mut acc_path_slots[txr_leg],
                &mut acc_recomputed_roots[txr_leg],
                t.depth,
                cap,
                leg_ivs[txr_leg],
                4,
                region_base,
                &real,
            );
            for (i, j) in (lo..hi).enumerate() {
                let base = region_base + i * stride;
                for level in 0..t.depth {
                    let bit = (j >> level) & 1 == 1;
                    cell_pins_b.push((
                        d_col,
                        base + 2 * level,
                        LinExpr::constant(if bit { F128::ONE } else { F128::ZERO }),
                    ));
                }
                if !t.rim_flat.is_empty() && j == n_paths - 1 {
                    for level in 0..t.depth {
                        if (j >> level) & 1 == 0 {
                            for lane in 0..2 {
                                cell_pins_b.push((
                                    sib_cols[lane],
                                    base + 2 * level,
                                    LinExpr::constant(t.rim_flat[level][lane]),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // ===================================================================
    // Tx-body spine (block-level, chunked like the exact-state families):
    // per instance, one 32-slot leaf/wrap tile + one 64-slot compress tree
    // fill walk A's spine region. Real instances pin their statement wires
    // (payload lanes → IN cells, pad flush = const pin), share their chain
    // digest wires between the tile C cells and the tree KID leaf cells,
    // pin the statement lanes to the remaining KID leaf cells, feed the
    // tree root into the wrap IN cells, and pin the wrap digest to the
    // tx-hash statement wires. Ghost instances (past the real count) are
    // canonical zero-body spines — valid chains satisfying the periodic
    // patterns, nothing downstream reads them.
    // ===================================================================
    if let Some(sp) = spine {
        let n_inst = sp.instances.len();
        let pad_absorb = spine_pad_absorb_flat();
        for blk in 0..k {
            for i in 0..spine_cap {
                let g = blk * spine_cap + i;
                let inst_flat = sp
                    .instances
                    .get(g)
                    .map(|inst| inst.flat.clone())
                    .unwrap_or_else(SpineInstanceFlat::ghost);
                let icols = build_spine_instance_columns(&inst_flat);
                let tree_abs = blk * per_tx_block_a + spine_tree_base + i * SPINE_TREE_SLOTS;
                let tile_abs = blk * per_tx_block_a + spine_tile_base + i * SPINE_TILE_SLOTS;
                for j in 0..STATE_SIZE {
                    cols[C0 + j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_c[j]);
                    s0[j][tree_abs..tree_abs + SPINE_TREE_SLOTS].copy_from_slice(&icols.tree_s0[j]);
                    s_out[j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_s_out[j]);
                    cols[C0 + j][tile_abs..tile_abs + SPINE_TILE_SLOTS]
                        .copy_from_slice(&icols.tile_c[j]);
                    s0[j][tile_abs..tile_abs + SPINE_TILE_SLOTS].copy_from_slice(&icols.tile_s0[j]);
                    s_out[j][tile_abs..tile_abs + SPINE_TILE_SLOTS]
                        .copy_from_slice(&icols.tile_s_out[j]);
                }
                for lane in 0..2 {
                    cols[KID0 + lane][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_kid[lane]);
                    cols[IN0 + lane][tile_abs..tile_abs + SPINE_TILE_SLOTS]
                        .copy_from_slice(&icols.tile_in[lane]);
                }
                let kid_half = SPINE_TREE_SLOTS / 2;
                spine_expo_kid0.extend_from_slice(&icols.tree_kid[0][..kid_half]);
                spine_expo_kid1.extend_from_slice(&icols.tree_kid[1][..kid_half]);
                spine_expo_c0.extend_from_slice(&icols.tree_c[0]);
                spine_expo_c1.extend_from_slice(&icols.tree_c[1]);

                if g >= n_inst {
                    continue; // ghost: no statement, no pins
                }
                let inst = &sp.instances[g];
                assert_eq!(
                    icols.tx_hash, inst.tx_hash_flat,
                    "spine instance {g}: region tx-body hash != the statement wires"
                );
                // Input chains: payload lanes → IN cells; pad flush const.
                for c4 in 0..SPINE_N_INPUT_LEAVES {
                    let head = tile_abs + 3 * c4;
                    let w4 = &inst.input_leaves_w[c4];
                    cell_pins_a.push((IN0, head, w4[0].clone()));
                    cell_pins_a.push((IN0 + 1, head, w4[1].clone()));
                    cell_pins_a.push((IN0, head + 1, w4[2].clone()));
                    cell_pins_a.push((IN0 + 1, head + 1, w4[3].clone()));
                    cell_pins_a.push((IN0, head + 2, LinExpr::constant(pad_absorb[0])));
                    cell_pins_a.push((IN0 + 1, head + 2, LinExpr::constant(pad_absorb[1])));
                }
                // Output chains: payload lanes → IN cells.
                for o8 in 0..SPINE_N_OUTPUT_LEAVES {
                    let head = tile_abs + 3 * SPINE_N_INPUT_LEAVES + 2 * o8;
                    let w4 = &inst.output_leaves_w[o8];
                    cell_pins_a.push((IN0, head, w4[0].clone()));
                    cell_pins_a.push((IN0 + 1, head, w4[1].clone()));
                    cell_pins_a.push((IN0, head + 1, w4[2].clone()));
                    cell_pins_a.push((IN0 + 1, head + 1, w4[3].clone()));
                }
                // Chain digests: ONE wire pinned to BOTH the tile C cell and
                // the tree KID leaf cell (the leaf join).
                for t in 0..SPINE_N_INPUT_LEAVES + SPINE_N_OUTPUT_LEAVES {
                    let dslot = tile_abs
                        + if t < SPINE_N_INPUT_LEAVES {
                            spine_input_digest_slot(t)
                        } else {
                            spine_output_digest_slot(t - SPINE_N_INPUT_LEAVES)
                        };
                    let kslot = tree_abs + SPINE_TREE_KID_LEAF_BASE + 2 + t;
                    for lane in 0..2 {
                        let w = LinExpr::from_wire(b.alloc_f128(icols.chain_digests[t][lane]));
                        cell_pins_a.push((C0 + lane, dslot, w.clone()));
                        cell_pins_a.push((KID0 + lane, kslot, w));
                    }
                }
                // Statement lanes → the non-chain KID leaf cells
                // (L0 anchor, L1 fee, L14 coinbase, L15 pad).
                for (leaf, wpair) in [
                    (0usize, &inst.anchor_w),
                    (1, &inst.fee_w),
                    (14, &inst.coinbase_w),
                    (15, &inst.pad_w),
                ] {
                    let kslot = tree_abs + SPINE_TREE_KID_LEAF_BASE + leaf;
                    cell_pins_a.push((KID0, kslot, wpair[0].clone()));
                    cell_pins_a.push((KID0 + 1, kslot, wpair[1].clone()));
                }
                // Tree root → wrap IN (shared wire; the root cell is the
                // tree's C0/C1 at heap node 1's odd slot, index 3).
                for lane in 0..2 {
                    let w = LinExpr::from_wire(b.alloc_f128(icols.root[lane]));
                    cell_pins_a.push((C0 + lane, tree_abs + 3, w.clone()));
                    cell_pins_a.push((IN0 + lane, tile_abs + SPINE_TILE_WRAP_SLOT, w));
                }
                // Wrap digest → the tx-hash statement wires.
                for lane in 0..2 {
                    cell_pins_a.push((
                        C0 + lane,
                        tile_abs + SPINE_TILE_WRAP_SLOT,
                        inst.tx_hash_w[lane].clone(),
                    ));
                }
            }
        }
    }

    // ===================================================================
    // Walk A (once): the two capsule-leaf tile families over ALL K txs,
    // common-period patterns (+ the exact-state sponge tiles and the spine
    // tree/tile when handed off). The walk/substitution flatten in tx count.
    // ===================================================================
    let mut fixed: Vec<FixedPattern> = Vec::new();
    let iv_capsleaf = capsule_leaf_iv_flat();
    // Each capsule-leaf family rides the region-gated SPONGE term shape
    // (region-gated plain IN reads, CARRY as the duplex feed-forward
    // selector, the slot-0 IV patterns).
    let mut wallet_leaf_refs: Vec<(SpongeLeafRefs, usize)> = Vec::with_capacity(n_leaf_families);
    for f in 0..n_leaf_families {
        let base = fixed.len();
        fixed.push(common_period_ones(
            leaf_base(f),
            nq * leaf_stride,
            block_log_a,
        ));
        for pat in capsule_leaf_fixed_patterns(iv_capsleaf) {
            fixed.push(common_period_pattern(
                &pat.table,
                leaf_base(f),
                nq,
                block_log_a,
            ));
        }
        wallet_leaf_refs.push((
            SpongeLeafRefs {
                in_: [IN0, IN0 + 1],
                c: std::array::from_fn(|i| C0 + i),
                odd: base + 1, // the CARRY duplex selector
                iv: [base + 2, base + 3],
            },
            base, // the family's region gate
        ));
    }
    // Exact-state sponge family: a region-ones selector (gating its PLAIN
    // IN reads — the family's own substitution reads IN ungated, which in a
    // UNION would fire inside other families' slots) + the family's ODD/IV
    // patterns, all localized to the es region of every tx block. Committed
    // refs REMAP onto walk A's shared IN0/IN1 + C0..C3 columns.
    let es_sponge: Option<(SpongeLeafRefs, usize)> = es.map(|_| {
        let base = fixed.len();
        fixed.push(common_period_ones(
            es_leaf_base,
            es_leaf_cap * SPONGE_LEAF_SLOTS,
            block_log_a,
        ));
        for pat in sponge_leaf_fixed_patterns(slot_leaf_iv_flat()) {
            fixed.push(common_period_pattern(
                &pat.table,
                es_leaf_base,
                es_leaf_cap,
                block_log_a,
            ));
        }
        (
            SpongeLeafRefs {
                in_: [IN0, IN0 + 1],
                c: std::array::from_fn(|i| C0 + i),
                odd: base + 1,
                iv: [base + 2, base + 3],
            },
            base,
        )
    });
    // Spine families: the tree rides the SOURCE-TREE term shape on the shared
    // CODE/KID/C columns with its own patterns (LEAFODD identically zero — the
    // leaf level is external, its slots ghost); the tile rides the SPONGE term
    // shape (CHAIN as the carry selector, the per-slot IV table carrying all
    // three head tags) gated by its own region-ones pattern.
    let spine_refs: Option<(SourceTreeRefs, SpongeLeafRefs, usize)> = spine.map(|_| {
        let base = fixed.len();
        for pat in spine_tree_fixed_patterns() {
            fixed.push(common_period_pattern(
                &pat.table,
                spine_tree_base,
                spine_cap,
                block_log_a,
            ));
        }
        for pat in spine_tile_fixed_patterns() {
            fixed.push(common_period_pattern(
                &pat.table,
                spine_tile_base,
                spine_cap,
                block_log_a,
            ));
        }
        (
            SourceTreeRefs {
                code: [CODE0, CODE0 + 1],
                kid: [KID0, KID0 + 1],
                c: std::array::from_fn(|i| C0 + i),
                even_int: base,
                odd_int: base + 1,
                leafodd: base + 2,
                iv: [base + 3, base + 4],
            },
            SpongeLeafRefs {
                in_: [IN0, IN0 + 1],
                c: std::array::from_fn(|i| C0 + i),
                odd: base + 6, // the CHAIN carry selector
                iv: [base + 7, base + 8],
            },
            base + 5, // the tile REGION gate
        )
    });
    let meta_c: [usize; STATE_SIZE] = std::array::from_fn(|i| C0 + i);
    let committed: Vec<&[F128]> = cols.iter().map(|c| c.as_slice()).collect();
    let spine_union_spec: Option<SpineUnionSpec> =
        spine_refs.map(|(tree_refs, tile_refs, tile_region)| SpineUnionSpec {
            tree_refs,
            tile_refs,
            tile_region,
            kid_meta: [KID0, KID0 + 1],
            c_meta: [C0, C0 + 1],
            cap_log: spine_cap.trailing_zeros() as usize,
            tx_log: k.trailing_zeros() as usize,
            tree_base: spine_tree_base,
            block_log_a,
        });
    let spine_expo_cols: [&[F128]; 4] = [
        spine_expo_kid0.as_slice(),
        spine_expo_kid1.as_slice(),
        spine_expo_c0.as_slice(),
        spine_expo_c1.as_slice(),
    ];
    let native_u = run_union_native(
        &committed,
        &s0,
        &s_out,
        &fixed,
        &meta_c,
        &wallet_leaf_refs,
        es_sponge.as_ref(),
        spine_union_spec.as_ref(),
        spine_union_spec.as_ref().map(|_| &spine_expo_cols),
        w_log,
    );
    let mut slices: Vec<WitnessSlice> = cols
        .iter()
        .map(|c| alloc_column_slice(b, c, w_log).0)
        .collect();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-A columns");
    // The walk-A discharge transcript is RECORDED (not replayed in-trace):
    // its absorb/squeeze chain rides walk C's region-2 blocks below, where
    // the challenge wires the twins consumed pin to walk-C carry cells.
    let mut ch_a = FsChannelUnionRecorder::new(DOMAIN);
    claims.extend(discharge_union(
        b,
        &mut ch_a,
        &fixed,
        &meta_c,
        &wallet_leaf_refs,
        es_sponge.as_ref(),
        spine_union_spec.as_ref(),
        w_log,
        &native_u,
    ));
    let rec_a = ch_a.finish();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-A twin");

    // ===================================================================
    // Walk B (once): the two feed-forward wallet legs + the 2-permutation
    // exact-state / tx-root legs over ALL K txs, common-period patterns.
    // ===================================================================
    let mut fixed_b: Vec<FixedPattern> = Vec::new();
    let mut ff_specs: Vec<FfLegSpec> = Vec::with_capacity(2);
    for f in 0..2 {
        let base = fixed_b.len();
        let family = FfMerklePathFamily {
            depth: ff_depths[f],
            n_paths: nq,
        };
        for pat in ff_merkle_fixed_patterns(&family, iv_capsnode) {
            fixed_b.push(common_period_pattern(
                &pat.table,
                ff_bases[f],
                nq,
                block_log_b,
            ));
        }
        fixed_b.push(common_period_ones(
            ff_bases[f],
            nq * ff_strides[f],
            block_log_b,
        ));
        ff_specs.push(FfLegSpec {
            refs: FfMerkleFamilyRefs {
                cr: [4, 5],
                sib: [6, 7],
                d: 8,
                c: std::array::from_fn(|i| i),
                node: base,
                nodens: base + 1,
                start: base + 2,
                iv: [base + 3, base + 4],
            },
            region: base + 5,
        });
    }
    let mut legs: Vec<MerkleLeg> = Vec::with_capacity(n_legs);
    for f in 0..n_legs {
        let depth = leg_depths[f];
        let fixed_base = fixed_b.len();
        let family = MerklePathFamily {
            depth,
            n_paths: leg_caps[f],
        };
        for pat in merkle_fixed_patterns(&family, leg_ivs[f]) {
            fixed_b.push(common_period_pattern(
                &pat.table,
                meta_bases[f],
                leg_caps[f],
                block_log_b,
            ));
        }
        fixed_b.push(common_period_ones(
            meta_bases[f],
            family.n_slots(),
            block_log_b,
        ));
        legs.push(MerkleLeg {
            family,
            refs: union_merkle_refs(fixed_base),
            region: fixed_base + 8,
            committed_roots: std::mem::take(&mut acc_committed_roots[f]),
            entry_wires: std::mem::take(&mut acc_entry_wires[f]),
            root_wires: std::mem::take(&mut acc_root_wires[f]),
            path_slots: std::mem::take(&mut acc_path_slots[f]),
            recomputed_roots: std::mem::take(&mut acc_recomputed_roots[f]),
        });
    }
    let committed_b: Vec<&[F128]> = cb.iter().map(|c| c.as_slice()).collect();
    let native_b = run_merkle_union_native(
        &committed_b,
        &s0b,
        &soutb,
        &fixed_b,
        &cb_c,
        &ff_specs,
        &legs,
        w_log_b,
        DOMAIN_B,
    );
    let n_slices_a = slices.len();
    let slices_b: Vec<WitnessSlice> = cb
        .iter()
        .map(|c| alloc_column_slice(b, c, w_log_b).0)
        .collect();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-B columns");
    // Walk B's discharge transcript is recorded too (region-2 block).
    let mut ch_b = FsChannelUnionRecorder::new(DOMAIN_B);
    let (mut wb_claims, wb_cell_pins) = discharge_merkle_union(
        b, &mut ch_b, &fixed_b, &cb_c, &ff_specs, &legs, w_log_b, &native_b,
    );
    let rec_b = ch_b.finish();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-B twin");
    for c in wb_claims.iter_mut() {
        c.slice += n_slices_a;
    }
    slices.extend(slices_b);
    claims.extend(wb_claims);
    // The merkle discharge's per-cell pins (leg entries/roots) join the
    // walk-B cell pins (both index the walk-B slices).
    cell_pins_b.extend(wb_cell_pins);
    assert!(
        all_expands_ok,
        "all real-sibling octopus expands returned non-empty paths"
    );

    // Stage 2: resolve the per-cell reads/pins to R1CS constraints (pin_eq), NOT
    // link-IO opening claims. Each column is opened by its walk discharge (random
    // point), so every cell is bound (Schwartz-Zippel); pinning the algebra wire
    // to the cell binds it too, keeping the O(K) per-cell bindings out of the IO.
    // Walk-A cols index `slices` directly; walk-B cols are offset by
    // `n_slices_a`.
    for (col, slot, wire) in &cell_pins_a {
        pin_eq(b, wire, &slot_cell(&slices[*col], *slot));
    }
    for (col, slot, wire) in &cell_pins_b {
        pin_eq(b, wire, &slot_cell(&slices[n_slices_a + *col], *slot));
    }
    // Feed-forward root pins: `C + CR + D·(CR + SIB)` at each path's last
    // node slot == the FS-OBSERVED root wire (TRANSCRIPT-BINDING; every
    // cell is bound by the walk-B discharge's random-point openings, and
    // the pin is an R1CS row — flat in tx count).
    for (last_slot, root_wires) in &ff_root_pins {
        let d_cell = slot_cell(&slices[n_slices_a + 8], *last_slot);
        for lane in 0..2 {
            let c_cell = slot_cell(&slices[n_slices_a + lane], *last_slot);
            let cr_cell = slot_cell(&slices[n_slices_a + 4 + lane], *last_slot);
            let sib_cell = slot_cell(&slices[n_slices_a + 6 + lane], *last_slot);
            let mix = mul(b, &d_cell, &cr_cell.add(&sib_cell));
            pin_eq(b, &c_cell.add(&cr_cell).add(&mix), &root_wires[lane]);
        }
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: stage-2 A/B cell pins");

    // ===================================================================
    // Walk C (once): REGION 1 tiles the K txs' FRICHANL transcript channels;
    // REGION 2 carries the walk A / walk B / owner-auth walk-C′ discharge
    // TRANSCRIPT RECORDINGS as per-block chain blocks (tx-count flat). The
    // squeezed challenges every consumer (per-tx algebra AND the walk twins)
    // used are bound to carry cells; the absorbed data to A-lane cells. Walk
    // C's OWN discharge transcript stays an inline replay (`DOMAIN_C`) — a
    // walk cannot host its own transcript.
    // ===================================================================
    let rec_iv = FsChannelUnionRecorder::capacity_iv_flat();
    let mut recordings: Vec<&RecordedChannel> = vec![&rec_a, &rec_b];
    if let Some(rc) = oa_recording {
        recordings.push(rc);
    }
    let rec_specs: Vec<RecordingSpec> = recordings
        .iter()
        .map(|rc| RecordingSpec {
            layout: compile_duplex(&rc.ops),
            iv_flat: rec_iv,
            data: &rc.data_flat,
        })
        .collect();
    let u_c =
        build_duplex_union_with_recordings(&chan_layout, iv_c, &chan_data_streams, &rec_specs);
    let native_c = run_duplex_union_native(&u_c, DOMAIN_C);
    let n_slices_ab = slices.len();
    let slices_c: Vec<WitnessSlice> = u_c
        .committed
        .iter()
        .map(|c| alloc_column_slice(b, c, u_c.w_log).0)
        .collect();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-C columns");
    let mut ch_c = FsChannelTrace::new(b, DOMAIN_C);
    let mut wc_claims = discharge_duplex_union(b, &mut ch_c, &u_c, &native_c, 0);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-C twin (inline)");
    for c in wc_claims.iter_mut() {
        c.slice += n_slices_ab;
    }
    // Stage 2: the per-tx channel absorbs + squeezed challenges are tied to the
    // walk-C A/C cells by R1CS constraint (`pin_eq`), NOT per-cell opening
    // claims. Every A/C column is opened by the walk-C discharge's
    // selection/substitution (O(1) per column, already in `wc_claims`), so its
    // MLE — hence every cell — is bound; pinning the algebra wire to the cell
    // binds it too. This keeps the O(K·(n_data+n_chal)) channel bindings out of
    // the link IO entirely (they become ~K·(n_data+n_chal) R1CS rows, the
    // accepted per-tx algebra cost), so the channel is tx-flat in the IO.
    let per_tx_c = 1usize << u_c.block_log;
    for tx in 0..k {
        for (kk, &(slot, lane)) in u_c.layout.challenges.iter().enumerate() {
            let cell = slot_cell(&slices_c[u_c.refs.c[lane]], tx * per_tx_c + slot);
            pin_eq(b, &chan_chal_wires[tx][kk], &cell);
        }
        for (kk, &(slot, lane)) in chan_data_positions.iter().enumerate() {
            let cell = slot_cell(&slices_c[u_c.refs.a[lane]], tx * per_tx_c + slot);
            pin_eq(b, &chan_data_wires[tx][kk], &cell);
        }
    }
    // Region-2 recordings: same cell-pin discipline. Each recording's absorbed
    // data wires (the walk discharges' proof wires) pin to its block's A-lane
    // cells and its challenge wires (the values the discharge twins consumed)
    // pin to the carry cells — the walk then proves the whole transcript chain,
    // replacing the deleted inline permutation replays.
    for (r, rc) in recordings.iter().enumerate() {
        let (rec_layout, off) = &u_c.rec_blocks[r];
        assert_eq!(
            rc.challenge_wires.len(),
            rec_layout.challenges.len(),
            "recording {r} challenge count"
        );
        assert_eq!(
            rc.data_wires.len(),
            rec_layout.n_data,
            "recording {r} data count"
        );
        for (kk, &(slot, lane)) in rec_layout.challenges.iter().enumerate() {
            assert_eq!(
                rc.challenge_wires[kk].eval(b.values()),
                u_c.rec_challenges[r][kk],
                "recording {r} challenge {kk} lockstep"
            );
            let cell = slot_cell(&slices_c[u_c.refs.c[lane]], off + slot);
            pin_eq(b, &rc.challenge_wires[kk], &cell);
        }
        for (kk, &(slot, lane)) in duplex_data_positions(rec_layout).iter().enumerate() {
            let cell = slot_cell(&slices_c[u_c.refs.a[lane]], off + slot);
            pin_eq(b, &rc.data_wires[kk], &cell);
        }
    }
    slices.extend(slices_c);
    claims.extend(wc_claims);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: cell pins + recordings");

    // Resolve each claim's column index into its committed WitnessSlice.
    claims
        .into_iter()
        .map(|c| RegionPcsClaim {
            slice: slices[c.slice],
            point: c.point,
            value: c.value,
            native_point: c.native_point,
            native_value: c.native_value,
        })
        .collect()
}

// ===========================================================================
// [G] step 4 — the owner-authorization KSCHANNL transcript, discharged as a
// data-parallel duplex walk (walk C), the exact analogue of the wallet-PCS
// FRICHANL migration above. The owner-auth killshot's KSCHANNL channel (the
// `Poseidon2bChannel` transcript of `verify_owner_auth_killshot`, ~311
// permutations/tx replayed inline) moves off the per-tx inline replay onto ONE
// shared duplex walk, so owner-auth verification is transaction-count flat.
//
// Each killshot's terminal claim is the SAME `PendingAuthPcsObligation` the
// inline `verify_owner_auth_killshot_trace` produces — the wallet-PCS
// `(commitment_cap_lanes, num_vars, reduction:(r_B, b_final))` — so the
// wallet-PCS discharge above is UNCHANGED: this fn produces those obligations
// with `r_B`/`b_final` derived from the walk-C carry cells, and the caller feeds
// them to `discharge_auth_pcs_obligations_via_region`.
//
// The channel-INDEPENDENT owner-auth algebra (`owner_unified_final_evals`,
// `owner_combined_target_trace`, `owner_shift_weights_at_point`,
// `owner_boundary_*`) is reused verbatim from `super::owner_auth`; only the
// channel-DEPENDENT folds are re-expressed to read the squeezed challenges out
// of `chal_w` (the walk-C carry cells) rather than an inline `RawChannelTrace`,
// and the per-round coefficient absorbs are dropped (the walk binds the absorbed
// data via the A-lane cells). `owner_auth_region_tests` holds this against the
// inline twin (obligation parity + a PCS-level money negative + K-flatness).
// ===========================================================================

/// FS domain for the owner-auth walk-C duplex union (distinct from the
/// wallet-PCS `DOMAIN_C`).
const OWNER_AUTH_DOMAIN_C: &[u8] = b"owner-auth-region-duplex-union";

/// The multi-level RLC weights of `squeeze_alphas_trace` with the level
/// challenges SUPPLIED (walk-C carry cells) instead of squeezed:
/// `weight[i] = Π_j bases[j]^{digit_j(i)}` over the base-64 digits of `i`,
/// `bases.len() == rlc_levels(m)`. `weights[0]` is the build-time constant
/// `1` (so the `is_const() && constant == ONE` fast path in
/// `owner_boundary_w` / `verify_batch_eval_trace` fires exactly as inline);
/// for `m ≤ 64` this is the single-base power ladder.
fn owner_rlc_weights(b: &mut FieldR1csBuilder, bases: &[LinExpr], m: usize) -> Vec<LinExpr> {
    use noid_gkr::batch_eval::{rlc_levels, RLC_LEVEL_BASE};
    if m == 0 {
        return Vec::new();
    }
    assert_eq!(bases.len(), rlc_levels(m), "one carry cell per RLC level");
    let mut tables: Vec<Vec<LinExpr>> = Vec::with_capacity(bases.len());
    for (j, c) in bases.iter().enumerate() {
        let digits = if bases.len() == 1 {
            m
        } else {
            RLC_LEVEL_BASE.min((m - 1) / RLC_LEVEL_BASE.pow(j as u32) + 1)
        };
        let mut table = Vec::with_capacity(digits);
        let mut acc = LinExpr::constant(F128::ONE);
        for k in 0..digits {
            table.push(acc.clone());
            if k + 1 < digits {
                acc = if k == 0 { c.clone() } else { mul(b, &acc, c) };
            }
        }
        tables.push(table);
    }
    if bases.len() == 1 {
        return tables.pop().expect("single level");
    }
    (0..m)
        .map(|i| {
            let mut w = tables[0][i % RLC_LEVEL_BASE].clone();
            let mut x = i / RLC_LEVEL_BASE;
            for table in &tables[1..] {
                let d = x % RLC_LEVEL_BASE;
                x /= RLC_LEVEL_BASE;
                if d > 0 {
                    w = mul(b, &w, &table[d]);
                }
            }
            w
        })
        .collect()
}

/// Discharge K owner-authorization killshots IN-TRACE in ONE builder, replaying
/// every KSCHANNL transcript on ONE shared data-parallel duplex walk (walk C).
/// The region twin of the per-tx inline `verify_owner_auth_killshot_trace`.
///
/// Returns, per killshot, the SAME `PendingAuthPcsObligation` the inline twin
/// produces (`commitment_cap_lanes` + the reduced `(r_B, b_final)` claim), plus
/// every walk-C committed-column opening claim ([`RegionPcsClaim`]) for the
/// caller to thread through the link's public IO. The wallet-PCS discharge
/// consumes the obligations UNCHANGED.
///
/// Challenge order in the walk-C carry cells (`5·num_vars + 2 + L_b` total
/// with `L_b = rlc_levels(boundary constraints)`, class-fixed by
/// `owner_auth_channel_schedule`):
///   `[rho×nv, r_prime×nv, delta, r_double_prime×nv, boundary_bases×L_b,
///     boundary_point×nv, batch_alpha, r_B×nv]`.
/// The fold outputs `r_prime` / `r_double_prime` / `boundary_point` / `r_B` are
/// the REVERSE of their per-round challenge order (matching the inline twin).
pub fn discharge_owner_auth_killshots_via_region(
    b: &mut FieldR1csBuilder,
    trace_proofs: &[OwnerAuthProofTrace],
    trace_inputs: &[OwnerAuthPublicInputsTrace],
    native_proofs: &[OwnerAuthProofKillShot],
    native_inputs: &[OwnerAuthPublicInputs],
) -> (
    Vec<PendingAuthPcsObligation>,
    Vec<RegionPcsClaim>,
    RecordedChannel,
) {
    let k = trace_proofs.len();
    assert!(k >= 1, "at least one owner-auth killshot");
    assert_eq!(trace_inputs.len(), k, "one trace input per killshot");
    assert_eq!(native_proofs.len(), k, "one native proof per killshot");
    assert_eq!(native_inputs.len(), k, "one native input per killshot");

    // Class-fixed channel layout — tx 0 defines it; every tx shares the class.
    let num_vars = OWNER_AUTH_NUM_VARS;
    let chan_layout =
        compile_duplex(&owner_auth_channel_schedule(&native_proofs[0], &native_inputs[0]).ops);
    let chan_data_positions = duplex_data_positions(&chan_layout);
    let per_tx_block_c = chan_layout.slots.len().next_power_of_two();
    let block_log_c = per_tx_block_c.trailing_zeros() as usize;
    let iv_c = {
        let iv = capacity_iv(TAG_KSCHANNL);
        [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
    };

    let mut chan_data_streams: Vec<Vec<F128>> = Vec::with_capacity(k);
    let mut chan_chal_wires: Vec<Vec<LinExpr>> = Vec::with_capacity(k);
    let mut chan_data_wires: Vec<Vec<LinExpr>> = Vec::with_capacity(k);
    let mut obligations: Vec<PendingAuthPcsObligation> = Vec::with_capacity(k);

    for tx in 0..k {
        let proof_t = &trace_proofs[tx];
        let inputs_t = &trace_inputs[tx];
        let native = &native_proofs[tx];
        let inputs_n = &native_inputs[tx];
        let layout = inputs_t.layout;
        let nv = OWNER_AUTH_NUM_VARS;
        assert_eq!(nv, num_vars, "class fixity: all txs share num_vars");

        // This tx's channel schedule + concrete duplex columns (native); the
        // squeezed-challenge wires arrive in schedule order (see the doc above).
        let schedule = owner_auth_channel_schedule(native, inputs_n);
        assert_eq!(
            schedule.data_flat.len(),
            chan_layout.n_data,
            "class fixity: absorb data count"
        );
        let dcols = build_duplex_columns(&chan_layout, iv_c, &schedule.data_flat, block_log_c);
        let chal_w: Vec<LinExpr> = dcols
            .challenges
            .iter()
            .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
            .collect();
        // The boundary constraint count is the class parameter
        // `padded_slots · 4` (the schedule extractor draws the same count).
        let lb_expected = noid_gkr::batch_eval::rlc_levels(4);
        assert_eq!(
            chal_w.len(),
            5 * nv + 2 + lb_expected,
            "owner-auth channel challenge count"
        );

        // ----- Unified state sumcheck: rho + per-round folds from chal_w.
        let rho: Vec<LinExpr> = chal_w[0..nv].to_vec();
        let mut expected = LinExpr::zero();
        let mut r_prime_opt: Vec<Option<LinExpr>> = vec![None; nv];
        for round in 0..nv {
            // `evaluate_reconstructed` reconstructs c_1 from the running claim
            // (sum-check by construction, no pin); NO coeff absorb — the walk
            // binds the coefficients via the A-lane data wires.
            let challenge = chal_w[nv + round].clone();
            expected =
                proof_t.main_round_polys[round].evaluate_reconstructed(b, &expected, &challenge);
            r_prime_opt[nv - 1 - round] = Some(challenge);
        }
        let r_prime: Vec<LinExpr> = r_prime_opt.into_iter().map(Option::unwrap).collect();
        let (u_at_r, mds_lane, sigma_lane, rc_lane) =
            owner_unified_final_evals(b, &inputs_t.slot_live, &rho, &r_prime);
        let mut q_at_r = proof_t.main_state_at_r.clone();
        for j in 0..STATE_SIZE {
            let x_j = proof_t.main_state_lane_dec_at_r[j].add(&rc_lane[j]);
            let x_j_pow7 = b.pow7(&x_j);
            let pi_j = mul(b, &sigma_lane[j], &x_j_pow7).add(&mul(
                b,
                &sigma_lane[j].add_const(F128::ONE),
                &proof_t.main_state_lane_dec_at_r[j],
            ));
            q_at_r = q_at_r.add(&mul(b, &mds_lane[j], &pi_j));
        }
        let rhs = mul(b, &u_at_r, &q_at_r);
        pin_zero(b, &expected.add(&rhs));
        let main_red = OwnerUnifiedReductionTrace {
            r_prime,
            state_at_r: proof_t.main_state_at_r.clone(),
            state_lane_dec_at_r: proof_t.main_state_lane_dec_at_r.clone(),
        };

        // ----- Shift sumcheck: delta + per-round folds from chal_w.
        let delta = chal_w[2 * nv].clone();
        let target = owner_combined_target_trace(b, &main_red, &delta);
        let mut expected = target;
        let mut r_double_prime: Vec<LinExpr> = Vec::with_capacity(nv);
        for round in 0..nv {
            let challenge = chal_w[2 * nv + 1 + round].clone();
            expected = proof_t.shift_round_polys[round].evaluate(b, &expected.clone(), &challenge);
            r_double_prime.push(challenge);
        }
        r_double_prime.reverse();
        let w_at_r =
            owner_shift_weights_at_point(b, layout, &main_red.r_prime, &delta, &r_double_prime);
        let rhs = mul(b, &w_at_r, &proof_t.shift_state_at_r2);
        pin_zero(b, &expected.add(&rhs));

        // ----- Boundary sumcheck: the RLC level draws + per-round folds
        // from chal_w (rlc_levels(constraints) cells — 1 at every transaction
        // class, 2 once a class exceeds 64 boundary constraints).
        let constraints = owner_boundary_constraints(b, inputs_t, layout);
        let lb = noid_gkr::batch_eval::rlc_levels(constraints.len());
        let boundary_bases: Vec<LinExpr> =
            (0..lb).map(|j| chal_w[3 * nv + 1 + j].clone()).collect();
        let alphas = owner_rlc_weights(b, &boundary_bases, constraints.len());
        let target = owner_boundary_target(b, &constraints, &alphas);
        let mut expected = target;
        let mut boundary_point: Vec<LinExpr> = Vec::with_capacity(nv);
        for round in 0..nv {
            let challenge = chal_w[3 * nv + 1 + lb + round].clone();
            expected =
                proof_t.boundary_round_polys[round].evaluate(b, &expected.clone(), &challenge);
            boundary_point.push(challenge);
        }
        boundary_point.reverse();
        let w_at = owner_boundary_w(b, &constraints, &alphas, &boundary_point);
        let rhs = mul(b, &w_at, &proof_t.boundary_state_at_r);
        pin_zero(b, &expected.add(&rhs));

        // ----- Batch-eval reduction over the 3 state claims (main/shift/boundary).
        let claim_values = [
            main_red.state_at_r.clone(),
            proof_t.shift_state_at_r2.clone(),
            proof_t.boundary_state_at_r.clone(),
        ];
        let claim_points = [main_red.r_prime.clone(), r_double_prime, boundary_point];
        let batch_alpha = chal_w[4 * nv + 1 + lb].clone();
        let batch_alphas = owner_rlc_weights(b, std::slice::from_ref(&batch_alpha), 3);
        let mut claim = claim_values[0].clone();
        for i in 1..3 {
            claim = claim.add(&mul(b, &batch_alphas[i], &claim_values[i]));
        }
        let mut r_b: Vec<LinExpr> = Vec::with_capacity(nv);
        for round in 0..nv {
            let challenge = chal_w[4 * nv + 2 + lb + round].clone();
            claim = proof_t.batch.rounds[round].evaluate(b, &claim.clone(), &challenge);
            r_b.push(challenge);
        }
        r_b.reverse();
        let mut w_at = LinExpr::zero();
        for i in 0..3 {
            let eq = eq_ind_trace(b, &claim_points[i], &r_b);
            if batch_alphas[i].is_const() && batch_alphas[i].constant == F128::ONE {
                w_at = w_at.add(&eq);
            } else {
                w_at = w_at.add(&mul(b, &batch_alphas[i], &eq));
            }
        }
        let rhs = mul(b, &w_at, &proof_t.batch.b_final);
        pin_zero(b, &claim.add(&rhs));

        obligations.push(PendingAuthPcsObligation {
            commitment_cap_lanes: proof_t.commitment_cap_lanes.clone(),
            num_vars: nv,
            reduction: BatchEvalReductionTrace {
                point: r_b,
                value: proof_t.batch.b_final.clone(),
            },
        });

        // ----- Absorbed-data wires in schedule order (bound to the A-lane cells
        // after the loop). Order MUST mirror `owner_auth_channel_schedule`; the
        // eval assert is the safety net against any lane/ordering drift.
        let mut data_wires: Vec<LinExpr> = Vec::with_capacity(schedule.data_flat.len());
        // Step 0/1: owner public boundary.
        data_wires.push(inputs_t.tx_body_hash[0].clone());
        data_wires.push(inputs_t.tx_body_hash[1].clone());
        data_wires.push(inputs_t.expected_address[0].clone());
        data_wires.push(inputs_t.expected_address[1].clone());
        // Step 2: auth MLE commitment cap hashes (2 lanes per 32-byte hash).
        for lane in &proof_t.commitment_cap_lanes {
            data_wires.push(lane[0].clone());
            data_wires.push(lane[1].clone());
        }
        // Step 3: unified round coeffs then reduced state.
        for round in 0..nv {
            for c in &proof_t.main_round_polys[round].coeffs_no_linear {
                data_wires.push(c.clone());
            }
        }
        data_wires.push(proof_t.main_state_at_r.clone());
        for v in &proof_t.main_state_lane_dec_at_r {
            data_wires.push(v.clone());
        }
        // Step 4: shift round evals then reduced state.
        for round in 0..nv {
            data_wires.push(proof_t.shift_round_polys[round].evals_at_1_2[0].clone());
            data_wires.push(proof_t.shift_round_polys[round].evals_at_1_2[1].clone());
        }
        data_wires.push(proof_t.shift_state_at_r2.clone());
        // Step 5: boundary round evals then reduced state.
        for round in 0..nv {
            data_wires.push(proof_t.boundary_round_polys[round].evals_at_1_2[0].clone());
            data_wires.push(proof_t.boundary_round_polys[round].evals_at_1_2[1].clone());
        }
        data_wires.push(proof_t.boundary_state_at_r.clone());
        // Step 6: batch claim values (main/shift/boundary) then round evals.
        data_wires.push(proof_t.main_state_at_r.clone());
        data_wires.push(proof_t.shift_state_at_r2.clone());
        data_wires.push(proof_t.boundary_state_at_r.clone());
        for round in 0..nv {
            data_wires.push(proof_t.batch.rounds[round].evals_at_1_2[0].clone());
            data_wires.push(proof_t.batch.rounds[round].evals_at_1_2[1].clone());
        }
        assert_eq!(
            data_wires.len(),
            schedule.data_flat.len(),
            "owner-auth absorb data lane count"
        );
        for (kk, w) in data_wires.iter().enumerate() {
            assert_eq!(
                w.eval(b.values()),
                schedule.data_flat[kk],
                "owner-auth absorb data wire {kk}"
            );
        }

        chan_data_streams.push(schedule.data_flat.clone());
        chan_chal_wires.push(chal_w);
        chan_data_wires.push(data_wires);
    }

    // ===================================================================
    // Walk C (once): the K txs' KSCHANNL transcript channels tiled into ONE
    // duplex walk. The squeezed challenges the per-tx algebra consumed are pinned
    // to the carry cells; the absorbed proof data is pinned to the A-lane cells.
    // ONE walk discharges all K channels — transaction-count flat.
    // ===================================================================
    let u_c = build_duplex_union(&chan_layout, iv_c, &chan_data_streams);
    let native_c = run_duplex_union_native(&u_c, OWNER_AUTH_DOMAIN_C);
    let slices: Vec<WitnessSlice> = u_c
        .committed
        .iter()
        .map(|c| alloc_column_slice(b, c, u_c.w_log).0)
        .collect();
    // This walk-C′ discharge transcript is RECORDED: the wallet-PCS plural
    // hosts it as a region-2 block of ITS walk C (the recording's challenge
    // wires below pin to that walk's carry cells there).
    let mut rec_ch = FsChannelUnionRecorder::new(OWNER_AUTH_DOMAIN_C);
    let claims = discharge_duplex_union(b, &mut rec_ch, &u_c, &native_c, 0);
    // Stage 2: the per-tx channel absorbs + squeezed challenges are tied to the
    // walk-C A/C cells by R1CS constraint (`pin_eq`), NOT per-cell opening claims
    // — every A/C column is opened by the walk-C discharge (O(1) per column), so
    // each cell is bound; the pins are R1CS rows, keeping the channel flat in the
    // link IO.
    let per_tx_c = 1usize << u_c.block_log;
    for tx in 0..k {
        for (kk, &(slot, lane)) in u_c.layout.challenges.iter().enumerate() {
            let cell = slot_cell(&slices[u_c.refs.c[lane]], tx * per_tx_c + slot);
            pin_eq(b, &chan_chal_wires[tx][kk], &cell);
        }
        for (kk, &(slot, lane)) in chan_data_positions.iter().enumerate() {
            let cell = slot_cell(&slices[u_c.refs.a[lane]], tx * per_tx_c + slot);
            pin_eq(b, &chan_data_wires[tx][kk], &cell);
        }
    }

    // Resolve each claim's column index into its committed WitnessSlice.
    let region_claims = claims
        .into_iter()
        .map(|c| RegionPcsClaim {
            slice: slices[c.slice],
            point: c.point,
            value: c.value,
            native_point: c.native_point,
            native_value: c.native_value,
        })
        .collect();

    (obligations, region_claims, rec_ch.finish())
}

// ===========================================================================
// Capsule-geometry trace helpers.
// ===========================================================================

/// Raw flat lanes of a 32-byte capsule tree digest: the bytes ARE flat-basis
/// state words (the flat sponge/compress output), so each half reads back as
/// an F128 with NO basis change (a TOWER digest would map through φ
/// instead).
fn lanes_raw(d: &[u8; 32]) -> [F128; 2] {
    [
        raw_flat_lane(u128::from_le_bytes(d[..16].try_into().unwrap())),
        raw_flat_lane(u128::from_le_bytes(d[16..].try_into().unwrap())),
    ]
}

/// Allocate a capsule digest as two raw-flat wires (the walk-B ff column
/// cells and the walk-C data lanes carry exactly these values under the
/// flat→tower absorb convention).
fn alloc_digest_raw(b: &mut FieldR1csBuilder, d: &[u8; 32]) -> [LinExpr; 2] {
    let lanes = lanes_raw(d);
    [
        LinExpr::from_wire(b.alloc_f128(lanes[0])),
        LinExpr::from_wire(b.alloc_f128(lanes[1])),
    ]
}

/// The raw flat lane of the integer recomposed from witness bits (LSB
/// first): `Σ bit_i · raw_flat(2^i)` — linear in the transcript-bound bits.
/// This is the capsule leaf sponge's meta-lane form of a leaf index.
fn raw_lane_from_bits(bits: &[LinExpr]) -> LinExpr {
    let mut lane = LinExpr::zero();
    for (i, bit) in bits.iter().enumerate() {
        lane = lane.add(&bit.scale(raw_flat_lane(1u128 << i)));
    }
    lane
}

/// The eq tensor of witness bits (LSB first): entry `c` = `eq(bits, c)`.
/// `2^n − 1` multiplications; shared by every mux/twiddle that keys on the
/// same bits.
fn bit_eq_tensor(b: &mut FieldR1csBuilder, bits: &[LinExpr]) -> Vec<LinExpr> {
    let mut tensor = vec![LinExpr::constant(F128::ONE)];
    for bit in bits {
        let his: Vec<LinExpr> = tensor.iter().map(|t| mul(b, t, bit)).collect();
        let mut next = Vec::with_capacity(tensor.len() * 2);
        for (t, h) in tensor.iter().zip(his.iter()) {
            next.push(t.add(h));
        }
        next.extend(his);
        tensor = next;
    }
    tensor
}

/// Trace twin of `noid_fri_binius::capsule::capsule_fold16`: fold one
/// 16-symbol coset down four variables, `betas` highest-variable-first.
/// Per binary step the twiddle is the window's top basis vector
/// `2^(rc + before_log − 1)` — selected through the SHARED rc eq tensor as
/// `Σ_c eq(rc_bits, c) · flat(2^(c + before_log − 1) ⊕ 1)` (the native
/// `basis + 1` is folded into the constant), so the step costs ONE
/// multiplication: `s1 + (twiddle_sel + r)·s0`. 15 muls per fold.
fn capsule_fold16_trace(
    b: &mut FieldR1csBuilder,
    betas: &[LinExpr],
    rc_tensor: &[LinExpr],
    msg_log_before: usize,
    syms: &[LinExpr],
) -> LinExpr {
    assert_eq!(syms.len(), CAPSULE_LEAF_SYMBOLS);
    assert_eq!(betas.len(), CAPSULE_WIDE_LOG);
    assert_eq!(rc_tensor.len(), CAPSULE_RATE);
    let mut cur: Vec<LinExpr> = syms.to_vec();
    for (t, r) in betas.iter().enumerate() {
        let before_log = msg_log_before - t;
        // twiddle + 1, affine over the shared rc tensor (no new muls).
        let mut tw = LinExpr::zero();
        for (c, e) in rc_tensor.iter().enumerate() {
            let basis = Block128::from((1u128 << (c + before_log - 1)) ^ 1);
            tw = tw.add(&e.scale(flat_of(basis)));
        }
        let factor = tw.add(r);
        let half = cur.len() / 2;
        let mut next = Vec::with_capacity(half);
        for kk in 0..half {
            next.push(cur[kk + half].add(&mul(b, &cur[kk], &factor)));
        }
        cur = next;
    }
    cur.pop().expect("fold16 terminal")
}

/// Trace twin of `noid_fri_binius::capsule::capsule_encode`: CAPSULE_RATE
/// window transforms of the message (window `r` spans NTT basis
/// `[r, r + log_n)`), concatenated. Constant-basis butterflies — pure linear
/// algebra, 0 constraints.
fn capsule_encode_trace(message: &[LinExpr]) -> Vec<LinExpr> {
    let log_n = message.len().trailing_zeros() as usize;
    assert_eq!(message.len(), 1usize << log_n);
    let mut encoding = Vec::with_capacity(message.len() * CAPSULE_RATE);
    for round in 0..CAPSULE_RATE {
        let basis: Vec<Block128> = (round..round + log_n)
            .map(|i| Block128::from(1u128 << i))
            .collect();
        encoding.extend(forward_ntt_trace(message, &basis));
    }
    encoding
}

/// One feed-forward wallet leg's union wiring: column/pattern indices only
/// (entries, directions and roots bind through cell pins in the caller).
pub(crate) struct FfLegSpec {
    pub(crate) refs: FfMerkleFamilyRefs,
    pub(crate) region: usize,
}

/// Place one ff-Merkle family's columns into the shared walk-B tables:
/// CR → the shared E columns [4..6), SIB → [6..8), D → 8, plus the walk
/// state columns.
pub(crate) fn place_ff(
    cb: &mut [Vec<F128>],
    s0b: &mut [Vec<F128>; STATE_SIZE],
    soutb: &mut [Vec<F128>; STATE_SIZE],
    cols: &noid_ivc_core::deep_chain::ff_merkle::FfMerklePathColumns,
    meta_base: usize,
    n_slots: usize,
) {
    let rng = meta_base..meta_base + n_slots;
    for j in 0..2 {
        cb[4 + j][rng.clone()].copy_from_slice(&cols.cr[j][0..n_slots]);
        cb[6 + j][rng.clone()].copy_from_slice(&cols.sib[j][0..n_slots]);
    }
    cb[8][rng.clone()].copy_from_slice(&cols.d[0..n_slots]);
    for j in 0..STATE_SIZE {
        cb[j][rng.clone()].copy_from_slice(&cols.c[j][0..n_slots]);
        s0b[j][rng.clone()].copy_from_slice(&cols.s0[j][0..n_slots]);
        soutb[j][rng.clone()].copy_from_slice(&cols.s_out[j][0..n_slots]);
    }
}

fn phi(bl: Block128) -> F128 {
    flat_of_tower_u128(bl.0)
}

/// The tx-root region handoff: every transaction body-hash Merkle path to the
/// underlying universal 256-leaf tree root `M`, as ONE walk-B TAG_COMPRESS
/// leg. Entries are the SPINE tx-hash wires (the leaf closure); `root_w` is
/// `M` (the root closure), not the header `tx_root`. The block slot separately
/// binds `TAG_TXROOT(M, tx_count)` to the header. Direction bits are the
/// CONSTANT leaf-index bits and the last real path's right-hand siblings are
/// the zero-subtree padding constants — both become const cell pins on the
/// committed D/SIB cells.
pub struct TxRootRegionData {
    /// Universal transaction-tree depth; fixed to `TX_TREE_DEPTH == 8`.
    pub depth: usize,
    /// Underlying universal-tree root `M` wires — every path's expected root.
    pub root_w: [LinExpr; 2],
    pub root_flat: [F128; 2],
    /// One path per transaction, in tx order (path `j`'s leaf position is `j`).
    pub paths: Vec<TxRootPathRegion>,
    /// Zero-subtree digest lanes per level (`Z_0 = zero leaf`,
    /// `Z_{l+1} = compress(Z_l, Z_l)`) — the padding-rim constants.
    pub rim_flat: Vec<[F128; 2]>,
}

/// One tx-root path's region handoff. The direction bits are NOT carried:
/// they are the leaf-index bits of the path's position in
/// [`TxRootRegionData::paths`], const-pinned in the leg fill.
pub struct TxRootPathRegion {
    /// The spine tx-hash wires — the walk-B entry (shared-wire leaf closure).
    pub entry_w: [LinExpr; 2],
    pub entry_flat: [F128; 2],
    /// Sibling digests, flat lanes, `[..depth]`.
    pub siblings: Vec<[F128; 2]>,
}

/// The tx-body spine region handoff: every transaction's 59-permutation
/// spine hashed by the walk-A tile+tree families instead of the inline
/// killshot replay. One instance per block transaction (coinbase included),
/// in tx order.
pub struct SpineRegionData {
    pub instances: Vec<SpineInstanceRegion>,
}

/// One transaction's spine handoff: the statement's flat lanes (driving the
/// column fill) plus the statement WIRES the cell pins bind — the leaf
/// payload lanes, the four non-chain tree leaves and the tx-body-hash pair
/// (the same wires the tx-root leg and the owner-auth statements consume).
pub struct SpineInstanceRegion {
    pub flat: SpineInstanceFlat,
    pub input_leaves_w: Vec<[LinExpr; 4]>,
    pub output_leaves_w: Vec<[LinExpr; 4]>,
    pub anchor_w: [LinExpr; 2],
    pub fee_w: [LinExpr; 2],
    pub coinbase_w: [LinExpr; 2],
    pub pad_w: [LinExpr; 2],
    pub tx_hash_w: [LinExpr; 2],
    pub tx_hash_flat: [F128; 2],
}

/// The flat-basis capacity IV of a consensus domain tag (mirror of the
/// TAG_FRICHANL conversion at the walk-C setup: `[φ(iv_hi), φ(iv_lo)]`).
fn iv_flat_of_tag(tag: DomainTag) -> [F128; 2] {
    let iv = capacity_iv(tag);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

/// One real exact-state path of a walk-B leg chunk: the flat witness data
/// plus the statement wires the leg pins bind (entry = the paired slot-leaf
/// digest wires; root = the expected-root statement wires).
struct EsPathReal {
    entry_flat: [F128; 2],
    entry_w: [LinExpr; 2],
    siblings: Vec<[F128; 2]>,
    directions: Vec<bool>,
    root_flat: [F128; 2],
    root_w: [LinExpr; 2],
}

/// Fill ONE tx block's chunk of an exact-state walk-B Merkle leg: the real
/// paths (entries/roots = statement wires) then canonical ghost paths (entry
/// `[0,0]`, zero siblings, all-left — the recomputed root is a deterministic
/// constant of `(depth, iv)`) up to the leg's per-block capacity. Extends the
/// per-leg accumulators in path order so `discharge_merkle_union`'s generic
/// entry/root pin loop covers real and ghost paths alike.
#[allow(clippy::too_many_arguments)]
fn fill_es_merkle_leg(
    cb: &mut [Vec<F128>],
    s0b: &mut [Vec<F128>; STATE_SIZE],
    soutb: &mut [Vec<F128>; STATE_SIZE],
    acc_entry_wires: &mut Vec<[LinExpr; 2]>,
    acc_root_wires: &mut Vec<[LinExpr; 2]>,
    acc_committed_roots: &mut Vec<[F128; 2]>,
    acc_path_slots: &mut Vec<usize>,
    acc_recomputed_roots: &mut Vec<[F128; 2]>,
    depth: usize,
    cap: usize,
    iv_flat: [F128; 2],
    col_base: usize,
    region_base: usize,
    real: &[EsPathReal],
) {
    assert!(
        real.len() <= cap,
        "es leg chunk exceeds the per-block capacity"
    );
    let stride = (2 * depth).next_power_of_two();
    let mut witnesses = Vec::with_capacity(cap);
    for p in real {
        assert_eq!(p.siblings.len(), depth);
        assert_eq!(p.directions.len(), depth);
        witnesses.push(MerklePathWitness {
            entry: p.entry_flat,
            siblings: p.siblings.clone(),
            directions: p.directions.clone(),
        });
    }
    for _ in real.len()..cap {
        witnesses.push(MerklePathWitness {
            entry: [F128::ZERO; 2],
            siblings: vec![[F128::ZERO; 2]; depth],
            directions: vec![false; depth],
        });
    }
    let family = MerklePathFamily {
        depth,
        n_paths: cap,
    };
    let fam_wlog = (cap * stride).next_power_of_two().trailing_zeros() as usize;
    let mcols = build_merkle_path_columns(&family, iv_flat, &witnesses, fam_wlog);
    place_merkle(cb, s0b, soutb, &mcols, col_base, region_base, cap * stride);
    for (i, p) in real.iter().enumerate() {
        assert_eq!(
            mcols.roots[i], p.root_flat,
            "es path recomputed root != the expected-root statement"
        );
        acc_entry_wires.push(p.entry_w.clone());
        acc_root_wires.push(p.root_w.clone());
        acc_committed_roots.push(p.root_flat);
        acc_path_slots.push(region_base + i * stride);
    }
    for i in real.len()..cap {
        let r = mcols.roots[i];
        acc_entry_wires.push([LinExpr::zero(), LinExpr::zero()]);
        acc_root_wires.push([LinExpr::constant(r[0]), LinExpr::constant(r[1])]);
        acc_committed_roots.push(r);
        acc_path_slots.push(region_base + i * stride);
    }
    acc_recomputed_roots.extend(mcols.roots.iter().copied());
}

pub(crate) fn alloc_column_slice(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> (WitnessSlice, Vec<LinExpr>) {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    let wires: Vec<LinExpr> = col
        .iter()
        .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
        .collect();
    for _ in col.len()..block {
        b.alloc_f128(F128::ZERO);
    }
    (WitnessSlice { log2_len, index }, wires)
}

/// The boolean point selecting slot `s` in `w_log` coordinates.
pub(crate) fn slot_point(s: usize, w_log: usize) -> (Vec<LinExpr>, Vec<F128>) {
    let lin = (0..w_log)
        .map(|bb| {
            LinExpr::constant(if (s >> bb) & 1 == 1 {
                F128::ONE
            } else {
                F128::ZERO
            })
        })
        .collect();
    let nat = (0..w_log)
        .map(|bb| {
            if (s >> bb) & 1 == 1 {
                F128::ONE
            } else {
                F128::ZERO
            }
        })
        .collect();
    (lin, nat)
}

/// The committed cell at `slot` of `slice`, as a raw wire read. Bound by the
/// column's walk opening (Stage 2: pin an algebra wire to a cell instead of
/// emitting a per-cell opening claim — an R1CS row, not a link-IO lane).
pub(crate) fn slot_cell(slice: &WitnessSlice, slot: usize) -> LinExpr {
    LinExpr::from_wire(Wire((slice.start() + slot) as u32))
}

/// Rebuild a per-family stride-period pattern as a META-period table by
/// repeating its stride table `n_tiles` times starting at `base`, zero
/// elsewhere; `low_log = meta_p_log` localizes it to `[base, base + n·stride)`.
/// A COMMON-PERIOD pattern for the multi-tx tiling: place `stride_table`
/// `n_tiles` times at `offset` within ONE per-tx block of `2^block_log` slots,
/// `low_log = block_log`. Because the pattern is periodic over the tx block, it
/// fires in every tx for free and its MLE cost is `O(2^block_log)` (flat in the
/// tx count) — NOT the `O(2^w_log)` of a full-domain [`localize`].
pub(crate) fn common_period_pattern(
    stride_table: &[F128],
    offset: usize,
    n_tiles: usize,
    block_log: usize,
) -> FixedPattern {
    let block = 1usize << block_log;
    let stride = stride_table.len();
    let mut t = vec![F128::ZERO; block];
    for q in 0..n_tiles {
        let off = offset + q * stride;
        t[off..off + stride].copy_from_slice(stride_table);
    }
    FixedPattern::new(block_log, t)
}

/// A common-period selector: `1` over `[offset, offset + len)` within a per-tx
/// block of `2^block_log` slots, `low_log = block_log` (a region selector that
/// fires in every tx).
pub(crate) fn common_period_ones(offset: usize, len: usize, block_log: usize) -> FixedPattern {
    let block = 1usize << block_log;
    let mut t = vec![F128::ZERO; block];
    for s in offset..offset + len {
        t[s] = F128::ONE;
    }
    FixedPattern::new(block_log, t)
}

fn flat_mds_entry(e: usize, j: usize) -> F128 {
    noid_ivc_core::deep_chain::flat_mds(true)[e][j]
}

/// `arr[idx]` selected by the witness bits of `idx` (LSB first):
/// `Σ_c eq(bits, c)·arr[c]`. Reads every `arr` wire with a class-fixed
/// coefficient structure — the block-dependence lives only in the boolean bit
/// values — so it replaces a native `arr[native_idx]` read whose selected wire
/// (and thus the constraint's column) drifts with the query position.
/// `arr.len()` must equal `2^bits.len()`.
fn select_by_bits(b: &mut FieldR1csBuilder, bits: &[LinExpr], arr: &[LinExpr]) -> LinExpr {
    debug_assert_eq!(arr.len(), 1usize << bits.len(), "select_by_bits arity");
    let tensor = bit_eq_tensor(b, bits);
    let mut acc = LinExpr::zero();
    for (t, a) in tensor.iter().zip(arr.iter()) {
        acc = acc.add(&mul(b, t, a));
    }
    acc
}

/// Trace α-power MDS weights `m[j] = Σ_e α^{e+1}·flat(MDS[e][j])`.
fn mds_alpha_weights(b: &mut FieldR1csBuilder, alpha: &LinExpr) -> (Vec<LinExpr>, Vec<LinExpr>) {
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        ap.push(acc.clone());
    }
    let m = (0..STATE_SIZE)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&ap[e].scale(flat_mds_entry(e, j)));
            }
            a
        })
        .collect();
    (m, ap)
}

// ---------------------------------------------------------------------------
// Internal claim record (global column index; resolved to a WitnessSlice at the
// end into a RegionPcsClaim).
// ---------------------------------------------------------------------------
pub(crate) struct Claim {
    pub(crate) slice: usize,
    pub(crate) point: Vec<LinExpr>,
    pub(crate) value: LinExpr,
    pub(crate) native_point: Vec<F128>,
    pub(crate) native_value: F128,
}

// ===========================================================================
// WALK A — the leaf-union native/trace DAG.
// ===========================================================================
/// The spine families' union wiring: the tree rides the source-tree term
/// shape (own patterns, zero LEAFODD), the tile the region-gated sponge
/// shape, and the gated tiled exposure re-points into walk A through the
/// class-constant layout below.
struct SpineUnionSpec {
    tree_refs: SourceTreeRefs,
    tile_refs: SpongeLeafRefs,
    tile_region: usize,
    /// Walk-A columns the 4 exposure claims re-point into.
    kid_meta: [usize; 2],
    c_meta: [usize; 2],
    /// `log2` of the per-block instance capacity / the tx count.
    cap_log: usize,
    tx_log: usize,
    /// In-block offset of instance 0's tree (a multiple of
    /// `SPINE_TREE_SLOTS << cap_log`).
    tree_base: usize,
    block_log_a: usize,
}

impl SpineUnionSpec {
    fn local_log(&self) -> usize {
        (SPINE_TREE_SLOTS / 2).trailing_zeros() as usize
    }
    fn expo_wlog(&self) -> usize {
        self.local_log() + self.cap_log + self.tx_log
    }
    /// The constant high in-block bits selecting the spine-tree run:
    /// `tree_base >> (log2(SPINE_TREE_SLOTS) + cap_log)`, emitted LSB-first
    /// up to `block_log_a`.
    fn base_bits(&self) -> Vec<F128> {
        let start = self.local_log() + 1 + self.cap_log;
        assert_eq!(
            self.tree_base % (1usize << start),
            0,
            "spine tree base alignment"
        );
        let s = self.tree_base >> start;
        (start..self.block_log_a)
            .map(|bit| {
                if (s >> (bit - start)) & 1 == 1 {
                    F128::ONE
                } else {
                    F128::ZERO
                }
            })
            .collect()
    }
    /// Re-point a KID claim: `[rho_local, 0, rho_i, base bits, rho_tx]`.
    fn repoint_kid(&self, expo_point: &[F128]) -> Vec<F128> {
        let (rho_local, rest) = expo_point.split_at(self.local_log());
        let (rho_i, rho_tx) = rest.split_at(self.cap_log);
        let mut pt = rho_local.to_vec();
        pt.push(F128::ZERO);
        pt.extend_from_slice(rho_i);
        pt.extend(self.base_bits());
        pt.extend_from_slice(rho_tx);
        pt
    }
    /// Re-point a C window claim: `[1, rho_local, rho_i, base bits, rho_tx]`.
    fn repoint_c(&self, expo_point: &[F128]) -> Vec<F128> {
        let (rho_local, rest) = expo_point.split_at(self.local_log());
        let (rho_i, rho_tx) = rest.split_at(self.cap_log);
        let mut pt = vec![F128::ONE];
        pt.extend_from_slice(rho_local);
        pt.extend_from_slice(rho_i);
        pt.extend(self.base_bits());
        pt.extend_from_slice(rho_tx);
        pt
    }
    /// The internal-child gate over the tiled exposure domain.
    fn gate_pattern(&self) -> FixedPattern {
        spine_tree_internal_child_pattern()
    }
}

struct UnionNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<(usize, Vec<F128>, F128)>,
    /// ONE gated tiled exposure over all spine trees + its 4 re-pointed
    /// claims (present iff the spine families ride this union).
    spine_expo_proof: Option<ColumnRelationProof>,
    spine_expo_pending: Vec<(usize, Vec<F128>, F128)>,
}

/// Gate a sponge-shaped family's plain IN reads with its region-ones
/// pattern (native side). The ODD/CARRY-gated carries and the IV patterns
/// carry their own localized gates.
fn gated_sponge_native_terms(
    sr: &SpongeLeafRefs,
    region: usize,
    alpha: F128,
    terms: &mut Vec<RelationTerm>,
) {
    let mut t = sponge_leaf_substitution_terms(sr, alpha);
    for term in t.iter_mut() {
        if !term.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
            term.factors.insert(0, ColRef::Fixed(region));
        }
    }
    terms.extend(t);
}

fn union_native_terms(
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    alpha: F128,
) -> Vec<RelationTerm> {
    let mut terms = Vec::new();
    // The capsule-leaf tile families ride the region-gated sponge shape
    // (CARRY as the duplex selector). Their committed refs coincide, so the
    // claimed-ref set (and claim count) stays family-count independent.
    for (sr, region) in leaf_refs {
        gated_sponge_native_terms(sr, *region, alpha, &mut terms);
    }
    // Exact-state sponge family: same shape, its own patterns.
    if let Some((sr, region)) = es_sponge {
        gated_sponge_native_terms(sr, *region, alpha, &mut terms);
    }
    // Spine families: the tree is the SOURCE-TREE shape on the shared
    // CODE/KID/C columns with its own patterns (LEAFODD ≡ 0, so the
    // `LEAFODD·CODE` terms vanish identically); the tile is the region-gated
    // sponge shape.
    if let Some(sp) = spine {
        terms.extend(source_tree_substitution_terms(&sp.tree_refs, alpha));
        gated_sponge_native_terms(&sp.tile_refs, sp.tile_region, alpha, &mut terms);
    }
    terms
}

#[allow(clippy::too_many_arguments)]
fn run_union_native(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    spine_expo_cols: Option<&[&[F128]; 4]>,
    w_log: usize,
) -> UnionNative {
    assert_eq!(
        spine.is_some(),
        spine_expo_cols.is_some(),
        "spine expo columns"
    );
    let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(DOMAIN);
    let mut ch_v = FsLaneChallenger::new(DOMAIN);
    let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(meta_c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        &mut ch_p,
    );
    let sel_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &sel_terms,
        fixed,
        &sel_proof,
        &mut ch_v,
    )
    .expect("native selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms)
        .iter()
        .zip(sel_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }

    let groups = vec![LaneClaimGroup {
        point: sel_point,
        values: gv,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_native_terms(leaf_refs, es_sponge, spine, alpha);
    let mut target = F128::ZERO;
    let mut p = F128::ONE;
    for e in 0..STATE_SIZE {
        p = p * alpha;
        target += p * terminal.values[e];
    }
    let (sub_proof, _, _) = prove_column_relation(
        target,
        &terminal.point,
        &sub_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        &mut ch_p,
    );
    let sub_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &sub_terms,
        fixed,
        &sub_proof,
        &mut ch_v,
    )
    .expect("native substitution");
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms)
        .iter()
        .zip(sub_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt =
                    verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
                pending.push((*c, pt, pr.final_value));
                shifts.push((0usize, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) = noid_ivc_core::deep_chain::relations::prove_shift_discharge_pow2(
                    committed[*c],
                    &sub_point,
                    *v,
                    1,
                    &mut ch_p,
                );
                let pt = noid_ivc_core::deep_chain::relations::verify_shift_discharge_pow2(
                    w_log, &sub_point, *v, 1, &pr, &mut ch_v,
                )
                .expect("shift2");
                pending.push((*c, pt, pr.final_value));
                shifts.push((1usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }

    // ONE gated tiled exposure over all spine trees (present iff the spine
    // families ride this union): `0 = Σ eq·GATE·Σ γ^{i+1}·[KID_lo + C(2w+1)]`
    // over the (K·cap)-instance tiled domain; the 4 terminal claims re-point
    // into walk A's KID/C at the class-constant spine layout — flat in tx
    // count. Ghost instances satisfy the relation (their KID low half IS the
    // window image at internal children by construction).
    let mut spine_expo_proof = None;
    let mut spine_expo_pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();
    if let (Some(sp), Some(se_cols)) = (spine, spine_expo_cols) {
        let gamma = ch_p.sample_f128();
        assert_eq!(gamma, ch_v.sample_f128());
        let expo_terms = spine_tree_exposure_terms([0, 1], [2, 3], 0, gamma);
        let expo_fixed = vec![sp.gate_pattern()];
        let rho_e = ch_p.sample_f128_vec(sp.expo_wlog());
        let _ = ch_v.sample_f128_vec(sp.expo_wlog());
        let (proof, _, _) = prove_column_relation(
            F128::ZERO,
            &rho_e,
            &expo_terms,
            &RelationColumns {
                committed: se_cols,
                internal: &[],
                fixed: &expo_fixed,
            },
            &mut ch_p,
        );
        let expo_point = verify_column_relation(
            sp.expo_wlog(),
            F128::ZERO,
            &rho_e,
            &expo_terms,
            &expo_fixed,
            &proof,
            &mut ch_v,
        )
        .expect("native spine tiled exposure");
        for (r, v) in claimed_refs(&expo_terms)
            .iter()
            .zip(proof.final_values.iter())
        {
            match r {
                ColRef::Committed(ll) => {
                    spine_expo_pending.push((sp.kid_meta[*ll], sp.repoint_kid(&expo_point), *v));
                }
                ColRef::Window { col, .. } => {
                    spine_expo_pending.push((sp.c_meta[*col - 2], sp.repoint_c(&expo_point), *v));
                }
                _ => unreachable!(),
            }
        }
        spine_expo_proof = Some(proof);
    }

    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native lockstep");
    UnionNative {
        sel_proof,
        walk_proof,
        sub_proof,
        shifts,
        pending,
        spine_expo_proof,
        spine_expo_pending,
    }
}

/// One source-tree-shaped trace term block (the spine tree rides this shape
/// with its own pattern indices).
fn tree_trace_terms(m: &[LinExpr], st_refs: &SourceTreeRefs, terms: &mut Vec<RelationTermTrace>) {
    for i in 0..2 {
        let kid = ColRef::Committed(st_refs.kid[i]);
        let c_sh = ColRef::CommittedShift(st_refs.c[i]);
        let code = ColRef::Committed(st_refs.code[i]);
        for factors in [
            vec![ColRef::Fixed(st_refs.even_int), kid],
            vec![ColRef::Fixed(st_refs.odd_int), kid],
            vec![ColRef::Fixed(st_refs.odd_int), c_sh],
            vec![ColRef::Fixed(st_refs.leafodd), code],
        ] {
            terms.push(RelationTermTrace {
                coeff: m[i].clone(),
                factors,
            });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(st_refs.iv[j - 2])],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![
                ColRef::Fixed(st_refs.odd_int),
                ColRef::CommittedShift(st_refs.c[j]),
            ],
        });
    }
}

/// One region-gated sponge-shaped trace term block (the capsule-leaf tile
/// families, the exact-state sponge tiles and the spine leaf/wrap tile all
/// ride this shape).
fn gated_sponge_trace_terms(
    m: &[LinExpr],
    sr: &SpongeLeafRefs,
    region: usize,
    terms: &mut Vec<RelationTermTrace>,
) {
    for i in 0..2 {
        terms.push(RelationTermTrace {
            coeff: m[i].clone(),
            factors: vec![ColRef::Fixed(region), ColRef::Committed(sr.in_[i])],
        });
        terms.push(RelationTermTrace {
            coeff: m[i].clone(),
            factors: vec![ColRef::Fixed(sr.odd), ColRef::CommittedShift(sr.c[i])],
        });
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(sr.iv[j - 2])],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(sr.odd), ColRef::CommittedShift(sr.c[j])],
        });
    }
}

/// Trace twin of `union_native_terms` with α-power MDS coefficients.
fn union_trace_terms(
    m: &[LinExpr],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
) -> Vec<RelationTermTrace> {
    let mut terms = Vec::new();
    for (sr, region) in leaf_refs {
        gated_sponge_trace_terms(m, sr, *region, &mut terms);
    }
    if let Some((sr, region)) = es_sponge {
        gated_sponge_trace_terms(m, sr, *region, &mut terms);
    }
    if let Some(sp) = spine {
        tree_trace_terms(m, &sp.tree_refs, &mut terms);
        gated_sponge_trace_terms(m, &sp.tile_refs, sp.tile_region, &mut terms);
    }
    terms
}

fn union_ref_terms(
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
) -> Vec<RelationTerm> {
    union_native_terms(leaf_refs, es_sponge, spine, F128::ONE)
}

#[allow(clippy::too_many_arguments)]
fn discharge_union(
    b: &mut FieldR1csBuilder,
    mut ch: &mut impl FsChannelOps,
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    w_log: usize,
    native: &UnionNative,
) -> Vec<Claim> {
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut cur = 0usize;
    let zero = LinExpr::zero();

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_terms: Vec<RelationTermTrace> = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Committed(meta_c[j])],
        });
        sel_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Internal(j)],
        });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_terms, fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(meta_c, F128::ONE));
    let mut gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    for (r, v) in sel_claimed.iter().zip(sel_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim {
                    slice: *col,
                    point: sel_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::Internal(j) => gv[*j] = v.clone(),
            _ => unreachable!(),
        }
    }

    let groups_e = vec![LaneClaimGroupTrace {
        point: sel_point,
        values: gv,
    }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let (m, ap) = mds_alpha_weights(b, &alpha);
    let sub_terms = union_trace_terms(&m, leaf_refs, es_sponge, spine);
    let ref_terms = union_ref_terms(leaf_refs, es_sponge, spine);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(
        b,
        &native.sub_proof,
        w_log,
        claimed_refs(&ref_terms).len(),
    );
    let sub_point = verify_column_relation_trace(
        b,
        &mut ch,
        w_log,
        &target,
        &terminal.point,
        &sub_terms,
        fixed,
        &sub_e,
    );
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&ref_terms)
        .iter()
        .zip(sub_e.final_values.iter())
    {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim {
                    slice: *col,
                    point: sub_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (shift_log, _col, ns) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt =
                    verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *shift_log, &se);
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim {
                    slice: *col,
                    point: pt,
                    value: se.final_value.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(shift_cursor, native.shifts.len(), "all shifts consumed");
    assert_eq!(cur, np.len(), "union pending lockstep");

    // ONE gated tiled SPINE exposure (mirror of `run_union_native`): the 4
    // terminal claims re-point into walk A's KID/C through the class-constant
    // spine layout — `[rho_local, 0, rho_i, base bits, rho_tx]` for KID and
    // `[1, rho_local, rho_i, base bits, rho_tx]` for the C window.
    if let Some(sp) = spine {
        let sp_native = native
            .spine_expo_proof
            .as_ref()
            .expect("spine union carries a spine exposure proof");
        let gamma = ch.sample_f128(b);
        let mut gp = LinExpr::constant(F128::ONE);
        let mut expo_terms: Vec<RelationTermTrace> = Vec::new();
        for i in 0..2 {
            gp = mul(b, &gp, &gamma);
            expo_terms.push(RelationTermTrace {
                coeff: gp.clone(),
                factors: vec![ColRef::Fixed(0), ColRef::Committed(i)],
            });
            expo_terms.push(RelationTermTrace {
                coeff: gp.clone(),
                factors: vec![
                    ColRef::Fixed(0),
                    ColRef::Window {
                        col: 2 + i,
                        stride_log: 1,
                        offset: 1,
                    },
                ],
            });
        }
        let expo_ref = spine_tree_exposure_terms([0, 1], [2, 3], 0, F128::ZERO);
        let expo_fixed = vec![sp.gate_pattern()];
        let rho_e = ch.sample_f128_vec(b, sp.expo_wlog());
        let expo_e = ColumnRelationProofTrace::alloc(
            b,
            sp_native,
            sp.expo_wlog(),
            claimed_refs(&expo_ref).len(),
        );
        let expo_point = verify_column_relation_trace(
            b,
            &mut ch,
            sp.expo_wlog(),
            &zero,
            &rho_e,
            &expo_terms,
            &expo_fixed,
            &expo_e,
        );
        let (rho_local, rest) = expo_point.split_at(sp.local_log());
        let (rho_i, rho_tx) = rest.split_at(sp.cap_log);
        let base_bits = sp.base_bits();
        let mut ec2 = 0usize;
        for (r, v) in claimed_refs(&expo_ref)
            .iter()
            .zip(expo_e.final_values.iter())
        {
            let (col, npt, nval) = &native.spine_expo_pending[ec2];
            ec2 += 1;
            let mut pt: Vec<LinExpr> = match r {
                ColRef::Committed(_) => {
                    let mut pt = rho_local.to_vec();
                    pt.push(LinExpr::constant(F128::ZERO));
                    pt
                }
                ColRef::Window { .. } => {
                    let mut pt = vec![LinExpr::constant(F128::ONE)];
                    pt.extend_from_slice(rho_local);
                    pt
                }
                _ => unreachable!(),
            };
            pt.extend_from_slice(rho_i);
            for bit in &base_bits {
                pt.push(LinExpr::constant(*bit));
            }
            pt.extend_from_slice(rho_tx);
            out.push(Claim {
                slice: *col,
                point: pt,
                value: v.clone(),
                native_point: npt.clone(),
                native_value: *nval,
            });
        }
        assert_eq!(
            ec2,
            native.spine_expo_pending.len(),
            "spine exposure pending lockstep"
        );
    }
    out
}

// ===========================================================================
// WALK B — the merkle-union.
// ===========================================================================
fn union_merkle_refs(fixed_base: usize) -> MerkleFamilyRefs {
    MerkleFamilyRefs {
        e: [4, 5],
        sib: [6, 7],
        d: 8,
        c: std::array::from_fn(|i| i),
        even: fixed_base,
        evenns: fixed_base + 1,
        evenstart: fixed_base + 2,
        odd: fixed_base + 3,
        oddns: fixed_base + 4,
        oddstart: fixed_base + 5,
        iv: [fixed_base + 6, fixed_base + 7],
    }
}

/// One Merkle-authentication leg placed in the shared walk-B meta domain.
pub(crate) struct MerkleLeg {
    family: MerklePathFamily,
    refs: MerkleFamilyRefs,
    region: usize,
    committed_roots: Vec<[F128; 2]>,
    entry_wires: Vec<[LinExpr; 2]>,
    /// TRANSCRIPT-BINDING: the FS-observed root wire per path (== the wire
    /// absorbed into the channel BEFORE the query draw). The walk-recomputed root
    /// cell is `pin_eq`'d to this wire, so the authenticated root is the
    /// transcript-seeded root — a prover cannot authenticate against a root chosen
    /// after the query positions are known.
    root_wires: Vec<[LinExpr; 2]>,
    /// The slot base of each path in the shared walk-B domain. Single tx: just
    /// `meta_base + path*stride`; the plural discharge tiles paths across tx
    /// blocks (`tx*per_tx_block_B + meta_base + q*stride`), so the entry/root
    /// claim slots read from here rather than a contiguous `meta_base + p*stride`.
    path_slots: Vec<usize>,
    /// The chain-replay-recomputed root per path (from `build_merkle_path_columns`),
    /// asserted == `committed_roots` (native consistency of the path replay).
    /// Accumulated across txs in the plural discharge.
    recomputed_roots: Vec<[F128; 2]>,
}

/// The zero-check relation terms: every 2-perm leg's direction booleanity,
/// plus every ff leg's CR-chain terms weighted by the drawn challenge λ
/// (lane weights λ, λ²). At an ff node slot BOTH a booleanity and a chain
/// term can be non-zero, so the chain group must carry a weight the prover
/// cannot predict: with λ drawn from the discharge channel, a pointwise
/// cancellation `bool(w) + λ·chain₀(w) + λ²·chain₁(w) = 0` forces every
/// group to vanish (Schwartz–Zippel in λ). Slots of DIFFERENT legs are
/// disjoint, so no cross-leg weight separation is needed.
fn union_zero_terms(legs: &[MerkleLeg], ff_specs: &[FfLegSpec], lambda: F128) -> Vec<RelationTerm> {
    let mut t = Vec::new();
    for leg in legs {
        t.extend(merkle_booleanity_terms(&leg.refs));
    }
    for spec in ff_specs {
        t.extend(ff_merkle_chain_terms(&spec.refs, lambda));
    }
    t
}

fn union_zero_terms_trace(
    b: &mut FieldR1csBuilder,
    legs: &[MerkleLeg],
    ff_specs: &[FfLegSpec],
    lambda: &LinExpr,
) -> Vec<RelationTermTrace> {
    let mut t: Vec<RelationTermTrace> = Vec::new();
    for leg in legs {
        for term in merkle_booleanity_terms(&leg.refs) {
            t.push(RelationTermTrace {
                coeff: LinExpr::constant(term.coeff),
                factors: term.factors.clone(),
            });
        }
    }
    // λ-power lane weights (the trace mirror of `ff_merkle_chain_terms`).
    let lp1 = lambda.clone();
    let lp2 = mul(b, lambda, lambda);
    for spec in ff_specs {
        let refs = &spec.refs;
        for (i, w) in [lp1.clone(), lp2.clone()].into_iter().enumerate() {
            let nodens = ColRef::Fixed(refs.nodens);
            let cr = ColRef::Committed(refs.cr[i]);
            let cr_sh = ColRef::CommittedShift(refs.cr[i]);
            let sib_sh = ColRef::CommittedShift(refs.sib[i]);
            let d_sh = ColRef::CommittedShift(refs.d);
            let c_sh = ColRef::CommittedShift(refs.c[i]);
            for factors in [
                vec![nodens, cr],
                vec![nodens, c_sh],
                vec![nodens, cr_sh],
                vec![nodens, d_sh, cr_sh],
                vec![nodens, d_sh, sib_sh],
            ] {
                t.push(RelationTermTrace {
                    coeff: w.clone(),
                    factors,
                });
            }
        }
    }
    t
}

fn union_sub_terms_native(
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    alpha: F128,
) -> Vec<RelationTerm> {
    let m = mds_weights_pub(alpha);
    let mut terms = Vec::new();
    // ff legs: the region-gated ghost-carry base (every lane), then the
    // NODE-gated wiring (which cancels the base at node slots and feeds the
    // CR/SIB mix — see `ff_merkle_substitution_terms`).
    for spec in ff_specs {
        for j in 0..STATE_SIZE {
            terms.push(RelationTerm {
                coeff: m[j],
                factors: vec![
                    ColRef::Fixed(spec.region),
                    ColRef::CommittedShift(spec.refs.c[j]),
                ],
            });
        }
        terms.extend(ff_merkle_substitution_terms(&spec.refs, alpha));
    }
    for leg in legs {
        let mut t = merkle_substitution_terms(&leg.refs, alpha);
        for term in t.iter_mut() {
            if !term.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
                term.factors.insert(0, ColRef::Fixed(leg.region));
            }
        }
        terms.extend(t);
    }
    terms
}

fn union_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let (m, ap) = mds_alpha_weights(b, alpha);
    let mut terms: Vec<RelationTermTrace> = Vec::new();

    for spec in ff_specs {
        let refs = &spec.refs;
        for j in 0..STATE_SIZE {
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![
                    ColRef::Fixed(spec.region),
                    ColRef::CommittedShift(refs.c[j]),
                ],
            });
        }
        let node = ColRef::Fixed(refs.node);
        for i in 0..2 {
            let cr = ColRef::Committed(refs.cr[i]);
            let sib = ColRef::Committed(refs.sib[i]);
            let d = ColRef::Committed(refs.d);
            let c_sh = ColRef::CommittedShift(refs.c[i]);
            for factors in [
                vec![node, c_sh],
                vec![node, cr],
                vec![node, d, cr],
                vec![node, d, sib],
            ] {
                terms.push(RelationTermTrace {
                    coeff: m[i].clone(),
                    factors,
                });
            }
            let j = 2 + i;
            let c_sh_j = ColRef::CommittedShift(refs.c[j]);
            for factors in [
                vec![node, c_sh_j],
                vec![node, sib],
                vec![node, d, cr],
                vec![node, d, sib],
                vec![ColRef::Fixed(refs.iv[i])],
            ] {
                terms.push(RelationTermTrace {
                    coeff: m[j].clone(),
                    factors,
                });
            }
        }
    }
    for leg in legs {
        let refs = &leg.refs;
        let region = ColRef::Fixed(leg.region);
        for i in 0..2 {
            let c_sh = ColRef::CommittedShift(refs.c[i]);
            let c_sh2 = ColRef::CommittedShift2(refs.c[i]);
            let sib = ColRef::Committed(refs.sib[i]);
            let sib_sh = ColRef::CommittedShift(refs.sib[i]);
            let e_col = ColRef::Committed(refs.e[i]);
            let e_sh = ColRef::CommittedShift(refs.e[i]);
            let d_col = ColRef::Committed(refs.d);
            let d_sh = ColRef::CommittedShift(refs.d);
            for factors in [
                vec![region, c_sh],
                vec![ColRef::Fixed(refs.evenstart), c_sh],
                vec![ColRef::Fixed(refs.evenns), d_col, c_sh],
                vec![ColRef::Fixed(refs.even), d_col, sib],
                vec![ColRef::Fixed(refs.evenstart), e_col],
                vec![ColRef::Fixed(refs.evenstart), d_col, e_col],
                vec![ColRef::Fixed(refs.odd), sib_sh],
                vec![ColRef::Fixed(refs.odd), d_sh, sib_sh],
                vec![ColRef::Fixed(refs.oddns), d_sh, c_sh2],
                vec![ColRef::Fixed(refs.oddstart), d_sh, e_sh],
            ] {
                terms.push(RelationTermTrace {
                    coeff: m[i].clone(),
                    factors,
                });
            }
        }
        for j in 2..STATE_SIZE {
            let c_sh = ColRef::CommittedShift(refs.c[j]);
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![region, c_sh],
            });
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.even), c_sh],
            });
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.iv[j - 2])],
            });
        }
    }
    (terms, ap)
}

pub(crate) struct MerkleUnionNative {
    pub(crate) zero_proof: ColumnRelationProof,
    pub(crate) zero_shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pub(crate) sel_proof: ColumnRelationProof,
    pub(crate) walk_proof: DeepChainWalkProof,
    pub(crate) sub_proof: ColumnRelationProof,
    pub(crate) shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pub(crate) pending: Vec<(usize, Vec<F128>, F128)>,
}

fn place_merkle(
    cb: &mut [Vec<F128>],
    s0b: &mut [Vec<F128>; STATE_SIZE],
    soutb: &mut [Vec<F128>; STATE_SIZE],
    cols: &MerklePathColumns,
    col_base: usize,
    meta_base: usize,
    n_slots: usize,
) {
    let rng = meta_base..meta_base + n_slots;
    for j in 0..2 {
        cb[col_base + j][rng.clone()].copy_from_slice(&cols.e[j][0..n_slots]);
        cb[col_base + 2 + j][rng.clone()].copy_from_slice(&cols.sib[j][0..n_slots]);
    }
    cb[col_base + 4][rng.clone()].copy_from_slice(&cols.d[0..n_slots]);
    for j in 0..STATE_SIZE {
        cb[j][rng.clone()].copy_from_slice(&cols.c[j][0..n_slots]);
        s0b[j][rng.clone()].copy_from_slice(&cols.s0[j][0..n_slots]);
        soutb[j][rng.clone()].copy_from_slice(&cols.s_out[j][0..n_slots]);
    }
}

/// Discharge one committed/shift claim set (native side): push Committed
/// claims to `pending`, run shift discharges into `shifts`.
#[allow(clippy::too_many_arguments)]
fn native_claim_pass(
    committed: &[&[F128]],
    w_log: usize,
    refs: &[ColRef],
    values: &[F128],
    point: &[F128],
    ch_p: &mut FsLaneChallenger,
    ch_v: &mut FsLaneChallenger,
    pending: &mut Vec<(usize, Vec<F128>, F128)>,
    shifts: &mut Vec<(usize, usize, ShiftDischargeProof)>,
) -> [F128; STATE_SIZE] {
    let mut internal = [F128::ZERO; STATE_SIZE];
    for (r, v) in refs.iter().zip(values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, point.to_vec(), *v)),
            ColRef::Internal(j) => internal[*j] = *v,
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], point, *v, ch_p);
                let pt = verify_shift_discharge(w_log, point, *v, &pr, ch_v).expect("shift");
                pending.push((*c, pt, pr.final_value));
                shifts.push((0usize, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) = prove_shift_discharge_pow2(committed[*c], point, *v, 1, ch_p);
                let pt =
                    verify_shift_discharge_pow2(w_log, point, *v, 1, &pr, ch_v).expect("shift2");
                pending.push((*c, pt, pr.final_value));
                shifts.push((1usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    internal
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_merkle_union_native(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    w_log: usize,
    domain: &[u8],
) -> MerkleUnionNative {
    let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();
    let mut zero_shifts = Vec::new();

    // Zero-check: 2-perm booleanity + λ-weighted ff CR-chain.
    let lambda = ch_p.sample_f128();
    assert_eq!(lambda, ch_v.sample_f128());
    let zero_terms = union_zero_terms(legs, ff_specs, lambda);
    let rho_b = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (zero_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_b,
        &zero_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        &mut ch_p,
    );
    let zero_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho_b,
        &zero_terms,
        fixed,
        &zero_proof,
        &mut ch_v,
    )
    .expect("native merkle-union zero-check");
    native_claim_pass(
        committed,
        w_log,
        &claimed_refs(&zero_terms),
        &zero_proof.final_values,
        &zero_point,
        &mut ch_p,
        &mut ch_v,
        &mut pending,
        &mut zero_shifts,
    );

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(cb_c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        &mut ch_p,
    );
    let sel_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &sel_terms,
        fixed,
        &sel_proof,
        &mut ch_v,
    )
    .expect("native merkle-union selection");
    let mut sel_shifts = Vec::new();
    let gv = native_claim_pass(
        committed,
        w_log,
        &claimed_refs(&sel_terms),
        &sel_proof.final_values,
        &sel_point,
        &mut ch_p,
        &mut ch_v,
        &mut pending,
        &mut sel_shifts,
    );
    assert!(sel_shifts.is_empty(), "carry selection claims no shifts");

    let groups = vec![LaneClaimGroup {
        point: sel_point,
        values: gv,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native merkle walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_sub_terms_native(ff_specs, legs, alpha);
    let mut target = F128::ZERO;
    let mut p = F128::ONE;
    for e in 0..STATE_SIZE {
        p = p * alpha;
        target += p * terminal.values[e];
    }
    let (sub_proof, _, _) = prove_column_relation(
        target,
        &terminal.point,
        &sub_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        &mut ch_p,
    );
    let sub_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &sub_terms,
        fixed,
        &sub_proof,
        &mut ch_v,
    )
    .expect("native merkle-union substitution");
    let mut shifts = Vec::new();
    native_claim_pass(
        committed,
        w_log,
        &claimed_refs(&sub_terms),
        &sub_proof.final_values,
        &sub_point,
        &mut ch_p,
        &mut ch_v,
        &mut pending,
        &mut shifts,
    );
    assert_eq!(
        ch_p.sample_f128(),
        ch_v.sample_f128(),
        "native merkle-union lockstep"
    );
    MerkleUnionNative {
        zero_proof,
        zero_shifts,
        sel_proof,
        walk_proof,
        sub_proof,
        shifts,
        pending,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn discharge_merkle_union(
    b: &mut FieldR1csBuilder,
    mut ch: &mut impl FsChannelOps,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    w_log: usize,
    native: &MerkleUnionNative,
) -> (Vec<Claim>, Vec<(usize, usize, LinExpr)>) {
    let mut out: Vec<Claim> = Vec::new();
    // Stage 2: the per-cell reads/pins (leg entries, leg roots) resolve to
    // pin_eq of the wire to the committed cell -- R1CS rows, not link-IO
    // claims. Every column is opened by this walk's zero-check / selection /
    // substitution (random point), so the cells are bound.
    let mut cell_pins: Vec<(usize, usize, LinExpr)> = Vec::new();
    let np = &native.pending;
    let mut cur = 0usize;
    let zero = LinExpr::zero();

    // Trace-side claim pass mirroring `native_claim_pass`.
    macro_rules! trace_claim_pass {
        ($refs:expr, $values:expr, $point:expr, $shifts:expr, $shift_cursor:ident, $gv:expr) => {
            for (r, v) in $refs.iter().zip($values.iter()) {
                match r {
                    ColRef::Committed(_) => {
                        let (col, npt, nval) = &np[cur];
                        cur += 1;
                        out.push(Claim {
                            slice: *col,
                            point: $point.clone(),
                            value: v.clone(),
                            native_point: npt.clone(),
                            native_value: *nval,
                        });
                    }
                    ColRef::Internal(j) => $gv[*j] = v.clone(),
                    ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                        let (shift_log, _col, ns) = &$shifts[$shift_cursor];
                        $shift_cursor += 1;
                        let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                        let pt = verify_shift_discharge_trace(
                            b, &mut ch, w_log, &$point, v, *shift_log, &se,
                        );
                        let (col, npt, nval) = &np[cur];
                        cur += 1;
                        out.push(Claim {
                            slice: *col,
                            point: pt,
                            value: se.final_value.clone(),
                            native_point: npt.clone(),
                            native_value: *nval,
                        });
                    }
                    _ => unreachable!(),
                }
            }
        };
    }

    // Zero-check: 2-perm booleanity + λ-weighted ff CR-chain (see
    // `union_zero_terms` for the λ soundness argument).
    let lambda = ch.sample_f128(b);
    let zero_ref = union_zero_terms(legs, ff_specs, F128::ONE);
    let n_zero = claimed_refs(&zero_ref).len();
    let rho_b = ch.sample_f128_vec(b, w_log);
    let zero_e = ColumnRelationProofTrace::alloc(b, &native.zero_proof, w_log, n_zero);
    let zero_terms_e = union_zero_terms_trace(b, legs, ff_specs, &lambda);
    let zero_point = verify_column_relation_trace(
        b,
        &mut ch,
        w_log,
        &zero,
        &rho_b,
        &zero_terms_e,
        fixed,
        &zero_e,
    );
    let mut zero_shift_cursor = 0usize;
    let mut unused_gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    trace_claim_pass!(
        claimed_refs(&zero_ref),
        zero_e.final_values,
        zero_point,
        native.zero_shifts,
        zero_shift_cursor,
        unused_gv
    );
    assert_eq!(
        zero_shift_cursor,
        native.zero_shifts.len(),
        "zero-check shifts consumed"
    );

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_terms: Vec<RelationTermTrace> = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Committed(cb_c[j])],
        });
        sel_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Internal(j)],
        });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_terms, fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(cb_c, F128::ONE));
    let mut gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    let mut sel_shift_cursor = 0usize;
    let no_shifts: Vec<(usize, usize, ShiftDischargeProof)> = Vec::new();
    trace_claim_pass!(
        sel_claimed,
        sel_e.final_values,
        sel_point,
        no_shifts,
        sel_shift_cursor,
        gv
    );
    assert_eq!(sel_shift_cursor, 0, "carry selection claims no shifts");

    let groups_e = vec![LaneClaimGroupTrace {
        point: sel_point,
        values: gv,
    }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let (sub_terms, ap) = union_sub_terms_trace(b, ff_specs, legs, &alpha);
    let ref_terms = union_sub_terms_native(ff_specs, legs, F128::ONE);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(
        b,
        &native.sub_proof,
        w_log,
        claimed_refs(&ref_terms).len(),
    );
    let sub_point = verify_column_relation_trace(
        b,
        &mut ch,
        w_log,
        &target,
        &terminal.point,
        &sub_terms,
        fixed,
        &sub_e,
    );
    let mut shift_cursor = 0usize;
    let mut unused_gv2: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    trace_claim_pass!(
        claimed_refs(&ref_terms),
        sub_e.final_values,
        sub_point,
        native.shifts,
        shift_cursor,
        unused_gv2
    );
    assert_eq!(
        shift_cursor,
        native.shifts.len(),
        "merkle-union shifts consumed"
    );
    assert_eq!(cur, np.len(), "merkle-union pending lockstep");

    // Per-leg entry pins (E == shared leaf digest wire) + recomputed-root pins
    // (C0/C1 at the root slot == the FS-OBSERVED root wire) -- both pin_eq, no
    // IO claims (flat in tx count). The ff legs' entry/direction/root pins are
    // collected by the caller (their root is a composite LinExpr).
    for leg in legs {
        let root_slot_local = 2 * (leg.family.depth - 1) + 1;
        for path in 0..leg.path_slots.len() {
            let entry_wire = leg.entry_wires[path].clone();
            let entry_slot = leg.path_slots[path];
            for lane in 0..2 {
                cell_pins.push((leg.refs.e[lane], entry_slot, entry_wire[lane].clone()));
            }
            // TRANSCRIPT-BINDING (flat): the recomputed-root column cell at
            // `root_slot` is `pin_eq`'d to the FS-OBSERVED root wire
            // (absorbed into the channel BEFORE the query draw). The C column
            // is opened at a random point by the Merkle walk, so the cell is
            // bound; the pin is an R1CS ROW, not an IO claim.
            let root_slot = leg.path_slots[path] + root_slot_local;
            for lane in 0..2 {
                assert_eq!(
                    leg.recomputed_roots[path][lane],
                    leg.committed_roots[path][lane]
                );
                cell_pins.push((
                    leg.refs.c[lane],
                    root_slot,
                    leg.root_wires[path][lane].clone(),
                ));
            }
        }
    }

    (out, cell_pins)
}

/// Drive the REAL noid_fri::Channel through the whole `capsule_verify`
/// transcript to the query draw (native cross-check): commitment absorb,
/// claim absorb, β draws, mid-root + h absorbs, the grind, then the query
/// positions over `nv + CAPSULE_LOG_RATE` bits.
fn derive_queries(proof: &AuthMleOpeningProof, primary_point: &[Block128]) -> Vec<usize> {
    let commitment = &proof.commitment;
    let opening = &proof.opening;
    let nv = commitment.log_rows;

    let mut channel = Channel::new();
    absorb_capsule_commitment(&mut channel, commitment);
    channel.observe_field_elem(Block128::from(CAPSULE_OPEN_TAG));
    channel.observe_field_elem(opening.value);
    channel.observe_field_elems(primary_point);
    channel.observe_field_elems(&opening.upper_partial_evals);
    let _beta: Vec<Block128> = channel.get_random_points(CAPSULE_TAU);
    // Mid root: flat digest lanes absorbed flat→tower (the capsule digest
    // convention).
    let lo = u128::from_le_bytes(opening.mid_root[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(opening.mid_root[16..].try_into().unwrap());
    channel.observe_field_elem(Block128::from(flat_to_tower_u128(lo)));
    channel.observe_field_elem(Block128::from(flat_to_tower_u128(hi)));
    channel.observe_field_elems(&opening.h_evals);
    // Grind.
    channel.observe_field_elem(Block128::from(opening.grind_nonce as u128));
    let ground = channel.get_random_point();
    assert_eq!(
        ground.0 & ((1u128 << CAPSULE_GRIND_BITS) - 1),
        0,
        "native grind check"
    );
    let mask = (1u128 << (nv + CAPSULE_LOG_RATE)) - 1;
    channel
        .get_random_points(CAPSULE_NUM_QUERIES)
        .iter()
        .map(|e| (e.0 & mask) as usize)
        .collect()
}

// ===========================================================================
// WALK C — the duplex-channel union (the [G] step 4 Stage 1 channel-flatness
// mechanism).
//
// Each transaction's wallet-PCS transcript channel (a Poseidon2b duplex) is one
// permutation chain, just like the leaf / Merkle families. The K channels tile a
// common per-tx block period, so ONE carry-selection + ONE deep-chain walk + ONE
// substitution discharge them all — the walk is logarithmic in the tiled domain,
// so the channel verification cost is transaction-count flat. The squeezed
// challenges are read out of the walk-discharged carry cells via opening claims
// (the same digest-read pattern the leaf families use); the absorbed data cells
// bind to the caller's proof wires the same way. This is what moves the ~311
// inline channel permutations per tx off the inline replay and onto a flat walk.
//
// Columns (all length P): A0=0, A1=1, C0=2..C3=5.
//
// The plural discharge drives these: it extracts each tx's channel schedule via
// `capsule_pcs_channel_schedule`, fills the duplex columns, and after the loop
// discharges the union walk and binds the squeezed challenges / absorbed data
// back to the per-tx algebra. `stage1_duplex_union_tests` gates the mechanism in
// isolation (native+trace, a full-PCS binding negative, K-flatness).
// ===========================================================================
pub(crate) struct DuplexUnion {
    pub(crate) committed: [Vec<F128>; 6],
    pub(crate) s0: [Vec<F128>; STATE_SIZE],
    pub(crate) s_out: [Vec<F128>; STATE_SIZE],
    pub(crate) fixed: Vec<FixedPattern>,
    pub(crate) refs: DuplexFamilyRefs,
    pub(crate) layout: DuplexLayout,
    pub(crate) w_log: usize,
    pub(crate) block_log: usize,
    /// One squeezed-challenge stream per real tx (schedule order).
    pub(crate) challenges: Vec<Vec<F128>>,
    /// REGION-2 recording blocks (caller order): each recorded discharge
    /// transcript's compiled layout and its dyadic domain offset. Empty for
    /// a single-region union.
    pub(crate) rec_blocks: Vec<(DuplexLayout, usize)>,
    /// Per-recording gated pattern-set refs (same committed columns,
    /// pattern indices after the region-1 set).
    pub(crate) rec_refs: Vec<DuplexFamilyRefs>,
    /// Per-recording squeezed challenges (native, schedule order).
    pub(crate) rec_challenges: Vec<Vec<F128>>,
}

/// Tile `data.len()` transactions' duplex channels into ONE walk-C domain at a
/// common per-tx block period. `data[t]` is tx `t`'s absorbed-data stream (flat,
/// length `layout.n_data`). The tile count is padded to a power of two with
/// CANONICAL GHOST channel blocks (IV-seeded, zero-data channels) — NOT
/// `perm([0;4])` ghost slots: the duplex substitution's leading carry term is
/// ungated, so every block must be a valid IV-seeded chain (the START pattern
/// cancels the cross-block carry in char 2, re-seeding each block).
pub(crate) fn build_duplex_union(
    layout: &DuplexLayout,
    iv_flat: [F128; 2],
    data: &[Vec<F128>],
) -> DuplexUnion {
    let per_tx = layout.slots.len().next_power_of_two();
    let block_log = per_tx.trailing_zeros() as usize;
    let k = data.len();
    let w_log = (k.max(1) * per_tx).next_power_of_two().trailing_zeros() as usize;
    let p = 1usize << w_log;
    let n_blocks = p / per_tx;

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges = Vec::with_capacity(k);
    let zero_data = vec![F128::ZERO; layout.n_data];

    for blk in 0..n_blocks {
        let d = data.get(blk).unwrap_or(&zero_data);
        let cols = build_duplex_columns(layout, iv_flat, d, block_log);
        let off = blk * per_tx;
        for j in 0..2 {
            committed[j][off..off + per_tx].copy_from_slice(&cols.a[j]);
        }
        for j in 0..STATE_SIZE {
            committed[2 + j][off..off + per_tx].copy_from_slice(&cols.c[j]);
            s0[j][off..off + per_tx].copy_from_slice(&cols.s0[j]);
            s_out[j][off..off + per_tx].copy_from_slice(&cols.s_out[j]);
        }
        if blk < k {
            challenges.push(cols.challenges);
        }
    }
    let fixed = duplex_fixed_patterns(layout, iv_flat, block_log);
    let refs = duplex_family_refs(0, 0);
    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs,
        layout: layout.clone(),
        w_log,
        block_log,
        challenges,
        rec_blocks: Vec::new(),
        rec_refs: Vec::new(),
        rec_challenges: Vec::new(),
    }
}

/// A recorded LANECHAL discharge transcript riding walk C as a REGION-2
/// block: its compiled schedule, capacity IV and absorbed witness data
/// (flat). Recordings are per-BLOCK objects (one per walk discharge), so
/// region 2 is transaction-count FLAT.
pub(crate) struct RecordingSpec<'a> {
    pub(crate) layout: DuplexLayout,
    pub(crate) iv_flat: [F128; 2],
    pub(crate) data: &'a [F128],
}

/// Two-region walk-C domain. REGION 1 (`[0, 2^r1_log)`) tiles the K
/// transactions' channels at the per-tx block period exactly like
/// [`build_duplex_union`] (real blocks + canonical zero-data ghost
/// channels); REGION 2 appends each RECORDED walk-discharge transcript
/// ONCE as its own dyadic sub-block, packed in descending size order (so
/// every offset is self-aligned to its block size). The slots between and
/// after the regions are pure carry-chain ghosts.
///
/// Pattern discipline: every set's START/ABS/CONST patterns carry a
/// [`FixedPattern::gated`] hi-gate pinning its dyadic region, so no set's
/// constants fire in another's slots (regions of DIFFERENT periods share
/// one walk soundly). The substitution's leading carry term stays ungated:
/// every slot is a valid chain permutation — schedule slots, in-block
/// ghost tails, the inter-region gap and the domain tail all carry the
/// previous state forward, and each block start re-seeds its capacity IV
/// through its own gated START/const patterns (char-2: `(1+START)·C`
/// cancels the incoming carry).
pub(crate) fn build_duplex_union_with_recordings(
    layout: &DuplexLayout,
    iv_flat: [F128; 2],
    data: &[Vec<F128>],
    recordings: &[RecordingSpec<'_>],
) -> DuplexUnion {
    assert!(
        !recordings.is_empty(),
        "recording-free unions use build_duplex_union"
    );
    let per_tx = layout.slots.len().next_power_of_two();
    let block_log = per_tx.trailing_zeros() as usize;
    let k = data.len();
    let r1_len = (k.max(1) * per_tx).next_power_of_two();
    let r1_log = r1_len.trailing_zeros() as usize;

    let packing = pack_recordings(r1_len, recordings);
    let offsets = &packing.offsets;
    let w_log = packing.w_log;
    let p = 1usize << w_log;

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges = Vec::with_capacity(k);
    let zero_data = vec![F128::ZERO; layout.n_data];

    // Region 1: real channel blocks + zero-data ghost channels to the
    // region boundary (each block IV-re-seeded by the gated START).
    for blk in 0..r1_len / per_tx {
        let d = data.get(blk).unwrap_or(&zero_data);
        let cols = build_duplex_columns(layout, iv_flat, d, block_log);
        let off = blk * per_tx;
        for j in 0..2 {
            committed[j][off..off + per_tx].copy_from_slice(&cols.a[j]);
        }
        for j in 0..STATE_SIZE {
            committed[2 + j][off..off + per_tx].copy_from_slice(&cols.c[j]);
            s0[j][off..off + per_tx].copy_from_slice(&cols.s0[j]);
            s_out[j][off..off + per_tx].copy_from_slice(&cols.s_out[j]);
        }
        if blk < k {
            challenges.push(cols.challenges);
        }
    }

    let rec_challenges = fill_recording_region(
        &mut committed,
        &mut s0,
        &mut s_out,
        r1_len,
        &packing,
        recordings,
    );

    // Gated pattern sets: region 1 pinned to its dyadic prefix, each
    // recording to its own block. Both region boundaries are strictly
    // below the domain top (region 2 is non-empty), so no gate is empty.
    let mut fixed: Vec<FixedPattern> = duplex_fixed_patterns(layout, iv_flat, block_log)
        .into_iter()
        .map(|pat| pat.gated(r1_log, rec_hi_bits(0, r1_log, w_log)))
        .collect();
    let rec_refs = gate_recording_patterns(&mut fixed, &packing, recordings);

    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs: duplex_family_refs(0, 0),
        layout: layout.clone(),
        w_log,
        block_log,
        challenges,
        rec_blocks: recordings
            .iter()
            .enumerate()
            .map(|(r, rec)| (rec.layout.clone(), offsets[r]))
            .collect(),
        rec_refs,
        rec_challenges,
    }
}

/// Descending-size dyadic packing of recording blocks after a region-1
/// prefix of `r1_len` slots: each recording gets a self-aligned dyadic
/// block, `w_log` covers everything.
pub(crate) struct RecordingPacking {
    pub(crate) order: Vec<usize>,
    pub(crate) sizes: Vec<usize>,
    pub(crate) offsets: Vec<usize>,
    pub(crate) w_log: usize,
}

pub(crate) fn pack_recordings(r1_len: usize, recordings: &[RecordingSpec<'_>]) -> RecordingPacking {
    let sizes: Vec<usize> = recordings
        .iter()
        .map(|r| r.layout.slots.len().max(1).next_power_of_two())
        .collect();
    let s_max = *sizes.iter().max().expect("non-empty recordings");
    let mut order: Vec<usize> = (0..recordings.len()).collect();
    order.sort_by_key(|&r| std::cmp::Reverse(sizes[r]));
    let r2_base = r1_len.max(s_max);
    let mut offsets = vec![0usize; recordings.len()];
    let mut cur = r2_base;
    for &r in &order {
        debug_assert_eq!(cur % sizes[r], 0, "dyadic packing alignment");
        offsets[r] = cur;
        cur += sizes[r];
    }
    let w_log = cur.next_power_of_two().trailing_zeros() as usize;
    RecordingPacking {
        order,
        sizes,
        offsets,
        w_log,
    }
}

/// High-coordinate gate bits of the dyadic block at `off` (block log
/// `from`) inside a `w_log` domain.
pub(crate) fn rec_hi_bits(off: usize, from: usize, w_log: usize) -> Vec<bool> {
    (from..w_log).map(|c| (off >> c) & 1 == 1).collect()
}

/// Fill the recording blocks + the carry-ghost gap/tail slots of a
/// recording-bearing union domain (columns pre-sized to `2^packing.w_log`;
/// region 1 already filled up to `r1_len`). Returns each recording's
/// squeezed challenges.
pub(crate) fn fill_recording_region(
    committed: &mut [Vec<F128>; 6],
    s0: &mut [Vec<F128>; STATE_SIZE],
    s_out: &mut [Vec<F128>; STATE_SIZE],
    r1_len: usize,
    packing: &RecordingPacking,
    recordings: &[RecordingSpec<'_>],
) -> Vec<Vec<F128>> {
    let p = 1usize << packing.w_log;
    let mut rec_challenges: Vec<Vec<F128>> = vec![Vec::new(); recordings.len()];
    let mut carry: [F128; STATE_SIZE] = std::array::from_fn(|j| committed[2 + j][r1_len - 1]);
    let mut cursor = r1_len;
    let fill_carry = |committed: &mut [Vec<F128>; 6],
                      s0: &mut [Vec<F128>; STATE_SIZE],
                      s_out: &mut [Vec<F128>; STATE_SIZE],
                      carry: &mut [F128; STATE_SIZE],
                      from: usize,
                      to: usize| {
        for slot in from..to {
            let (g0, gout) = noid_ivc_core::deep_chain::source_tree::run_perm(*carry);
            for j in 0..STATE_SIZE {
                s0[j][slot] = g0[j];
                s_out[j][slot] = gout[j];
                committed[2 + j][slot] = gout[j];
            }
            *carry = gout;
        }
    };
    for &r in &packing.order {
        fill_carry(committed, s0, s_out, &mut carry, cursor, packing.offsets[r]);
        let rec = &recordings[r];
        let sz = packing.sizes[r];
        let s_log = sz.trailing_zeros() as usize;
        let cols = build_duplex_columns(&rec.layout, rec.iv_flat, rec.data, s_log);
        let off = packing.offsets[r];
        for j in 0..2 {
            committed[j][off..off + sz].copy_from_slice(&cols.a[j]);
        }
        for j in 0..STATE_SIZE {
            committed[2 + j][off..off + sz].copy_from_slice(&cols.c[j]);
            s0[j][off..off + sz].copy_from_slice(&cols.s0[j]);
            s_out[j][off..off + sz].copy_from_slice(&cols.s_out[j]);
        }
        rec_challenges[r] = cols.challenges;
        carry = std::array::from_fn(|j| committed[2 + j][off + sz - 1]);
        cursor = off + sz;
    }
    fill_carry(committed, s0, s_out, &mut carry, cursor, p);
    rec_challenges
}

/// Append each recording's gated 7-pattern set to `fixed` and return the
/// per-recording family refs (pattern indices after the existing sets).
pub(crate) fn gate_recording_patterns(
    fixed: &mut Vec<FixedPattern>,
    packing: &RecordingPacking,
    recordings: &[RecordingSpec<'_>],
) -> Vec<DuplexFamilyRefs> {
    let mut rec_refs = Vec::with_capacity(recordings.len());
    for (r, rec) in recordings.iter().enumerate() {
        let s_log = packing.sizes[r].trailing_zeros() as usize;
        let base = fixed.len();
        for pat in duplex_fixed_patterns(&rec.layout, rec.iv_flat, s_log) {
            fixed.push(pat.gated(s_log, rec_hi_bits(packing.offsets[r], s_log, packing.w_log)));
        }
        rec_refs.push(duplex_family_refs(0, base));
    }
    rec_refs
}

/// Substitution terms over a MULTI-REGION duplex domain: the ungated
/// leading carry once (`Σ_j m_j·C_j(w−1)` — every slot of every region and
/// ghost gap is a chain permutation), then each pattern set's gated
/// START/ABS/CONST wiring. The claimed refs stay the six A/C columns —
/// identical discharge plumbing to the single-set terms.
fn duplex_substitution_terms_multi(sets: &[DuplexFamilyRefs], alpha: F128) -> Vec<RelationTerm> {
    let flat = |v: u128| flat_of_tower_u128(v);
    let mut alphas = [F128::ZERO; STATE_SIZE];
    let mut pw = F128::ONE;
    for a in alphas.iter_mut() {
        pw = pw * alpha;
        *a = pw;
    }
    let m: [F128; STATE_SIZE] = std::array::from_fn(|j| {
        let mut acc = F128::ZERO;
        for e in 0..STATE_SIZE {
            acc += alphas[e] * flat(noid_poseidon2b::native::permutation::MDS_FULL[e][j]);
        }
        acc
    });
    let mut terms = Vec::new();
    for j in 0..STATE_SIZE {
        terms.push(RelationTerm {
            coeff: m[j],
            factors: vec![ColRef::CommittedShift(sets[0].c[j])],
        });
    }
    for refs in sets {
        for j in 0..STATE_SIZE {
            terms.push(RelationTerm {
                coeff: m[j],
                factors: vec![ColRef::Fixed(refs.start), ColRef::CommittedShift(refs.c[j])],
            });
            if j < 2 {
                terms.push(RelationTerm {
                    coeff: m[j],
                    factors: vec![ColRef::Fixed(refs.abs[j]), ColRef::Committed(refs.a[j])],
                });
            }
            terms.push(RelationTerm {
                coeff: m[j],
                factors: vec![ColRef::Fixed(refs.consts[j])],
            });
        }
    }
    terms
}

/// The union's substitution terms: single-set unions keep the original
/// [`duplex_substitution_terms`] wiring byte-for-byte; recording-bearing
/// unions use the multi-set form.
pub(crate) fn duplex_union_sub_terms(u: &DuplexUnion, alpha: F128) -> Vec<RelationTerm> {
    if u.rec_refs.is_empty() {
        duplex_substitution_terms(&u.refs, alpha)
    } else {
        let mut sets = vec![u.refs];
        sets.extend(u.rec_refs.iter().copied());
        duplex_substitution_terms_multi(&sets, alpha)
    }
}

pub(crate) struct DuplexUnionNative {
    pub(crate) sel_proof: ColumnRelationProof,
    pub(crate) walk_proof: DeepChainWalkProof,
    pub(crate) sub_proof: ColumnRelationProof,
    pub(crate) shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pub(crate) pending: Vec<(usize, Vec<F128>, F128)>,
}

/// Native discharge of the whole channel union in ONE walk (mirror of
/// `run_leaf_union_native` with the duplex family's terms).
pub(crate) fn run_duplex_union_native(u: &DuplexUnion, domain: &[u8]) -> DuplexUnionNative {
    let committed: Vec<&[F128]> = u.committed.iter().map(|c| c.as_slice()).collect();
    let internal: Vec<&[F128]> = u.s_out.iter().map(|c| c.as_slice()).collect();
    let fixed = &u.fixed;
    let refs = &u.refs;
    let w_log = u.w_log;
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending = Vec::new();

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&refs.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns {
            committed: &committed,
            internal: &internal,
            fixed,
        },
        &mut ch_p,
    );
    let sel_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &sel_terms,
        fixed,
        &sel_proof,
        &mut ch_v,
    )
    .expect("native duplex selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms)
        .iter()
        .zip(sel_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }
    let groups = vec![LaneClaimGroup {
        point: sel_point,
        values: gv,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(&u.s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native duplex walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = duplex_union_sub_terms(u, alpha);
    let mut target = F128::ZERO;
    let mut p = F128::ONE;
    for e in 0..STATE_SIZE {
        p = p * alpha;
        target += p * terminal.values[e];
    }
    let (sub_proof, _, _) = prove_column_relation(
        target,
        &terminal.point,
        &sub_terms,
        &RelationColumns {
            committed: &committed,
            internal: &[],
            fixed,
        },
        &mut ch_p,
    );
    let sub_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &sub_terms,
        fixed,
        &sub_proof,
        &mut ch_v,
    )
    .expect("native duplex substitution");
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms)
        .iter()
        .zip(sub_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt =
                    verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
                pending.push((*c, pt, pr.final_value));
                shifts.push((0usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(
        ch_p.sample_f128(),
        ch_v.sample_f128(),
        "native duplex-union lockstep"
    );
    DuplexUnionNative {
        sel_proof,
        walk_proof,
        sub_proof,
        shifts,
        pending,
    }
}

/// Trace twin of `duplex_substitution_terms`: the α-batched walk-terminal wiring
/// `Σ_j m_j·[C_j(w−1) + START·C_j(w−1) + ABS_j·A_j + CONST_j]` (rate-lane absorbs
/// on j ∈ {0,1}), with `m_j = Σ_e α^{e+1}·flat(MDS[e][j])` built in-trace.
fn duplex_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    refs: &DuplexFamilyRefs,
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let (m, ap) = mds_alpha_weights(b, alpha);
    let mut terms = Vec::new();
    for j in 0..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::CommittedShift(refs.c[j])],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.start), ColRef::CommittedShift(refs.c[j])],
        });
        if j < 2 {
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.abs[j]), ColRef::Committed(refs.a[j])],
            });
        }
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.consts[j])],
        });
    }
    (terms, ap)
}

/// Trace twin of [`duplex_substitution_terms_multi`] (same term order).
fn duplex_sub_terms_trace_multi(
    b: &mut FieldR1csBuilder,
    sets: &[DuplexFamilyRefs],
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let (m, ap) = mds_alpha_weights(b, alpha);
    let mut terms = Vec::new();
    for j in 0..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::CommittedShift(sets[0].c[j])],
        });
    }
    for refs in sets {
        for j in 0..STATE_SIZE {
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.start), ColRef::CommittedShift(refs.c[j])],
            });
            if j < 2 {
                terms.push(RelationTermTrace {
                    coeff: m[j].clone(),
                    factors: vec![ColRef::Fixed(refs.abs[j]), ColRef::Committed(refs.a[j])],
                });
            }
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.consts[j])],
            });
        }
    }
    (terms, ap)
}

/// Discharge the shared channel union in-trace (mirror of `discharge_leaf_union`
/// for the duplex family). Column claims are offset by `base` in the caller's
/// global slice table. Returns the pending terminal claims on the A/C columns.
/// The caller supplies the discharge transcript channel: an inline
/// [`FsChannelTrace`] (walk C itself — a walk cannot host its own transcript),
/// or an [`FsChannelUnionRecorder`] whose recording rides another union.
pub(crate) fn discharge_duplex_union(
    b: &mut FieldR1csBuilder,
    mut ch: &mut impl FsChannelOps,
    u: &DuplexUnion,
    native: &DuplexUnionNative,
    base: usize,
) -> Vec<Claim> {
    let refs = &u.refs;
    let fixed = &u.fixed;
    let w_log = u.w_log;
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut np_cursor = 0usize;
    let zero = LinExpr::zero();

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_e_terms = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_e_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Committed(refs.c[j])],
        });
        sel_e_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Internal(j)],
        });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_e_terms, fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(&refs.c, F128::ONE));
    let mut gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    for (r, v) in sel_claimed.iter().zip(sel_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => {
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *c,
                    point: sel_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::Internal(j) => gv[*j] = v.clone(),
            _ => unreachable!(),
        }
    }
    let groups_e = vec![LaneClaimGroupTrace {
        point: sel_point,
        values: gv,
    }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let sub_native = duplex_union_sub_terms(u, F128::ONE);
    let (sub_e_terms, ap) = if u.rec_refs.is_empty() {
        duplex_sub_terms_trace(b, refs, &alpha)
    } else {
        let mut sets = vec![*refs];
        sets.extend(u.rec_refs.iter().copied());
        duplex_sub_terms_trace_multi(b, &sets, &alpha)
    };
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(
        b,
        &native.sub_proof,
        w_log,
        claimed_refs(&sub_native).len(),
    );
    let sub_point = verify_column_relation_trace(
        b,
        &mut ch,
        w_log,
        &target,
        &terminal.point,
        &sub_e_terms,
        fixed,
        &sub_e,
    );
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&sub_native)
        .iter()
        .zip(sub_e.final_values.iter())
    {
        match r {
            ColRef::Committed(c) => {
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *c,
                    point: sub_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::CommittedShift(_) => {
                let (sl, col, ns) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *sl, &se);
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *col,
                    point: pt,
                    value: se.final_value.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(np_cursor, np.len(), "duplex-union pending lockstep");
    out
}

/// Bind tx `t`'s already-allocated squeezed-challenge wires to the walk-C carry
/// cells: one opening claim per challenge on carry column `C_lane` at the
/// challenge's slot (the digest-read pattern). Because the C columns are opened
/// by the walk (proving they ARE the chain output) and each claim opens `C_lane`
/// at the exact slot, the bound wire is forced to the correct squeezed challenge
/// — the prover cannot use a different value. The plural uses this to bind the
/// in-loop challenge wires the per-tx algebra consumed.
pub(crate) fn bind_duplex_challenges(
    u: &DuplexUnion,
    t: usize,
    base: usize,
    chal_wires: &[LinExpr],
    out: &mut Vec<Claim>,
) {
    let per_tx = 1usize << u.block_log;
    assert_eq!(
        chal_wires.len(),
        u.layout.challenges.len(),
        "challenge wire count"
    );
    for (k, &(slot, lane)) in u.layout.challenges.iter().enumerate() {
        let gslot = t * per_tx + slot;
        let (pt_lin, pt_nat) = slot_point(gslot, u.w_log);
        out.push(Claim {
            slice: base + u.refs.c[lane],
            point: pt_lin,
            value: chal_wires[k].clone(),
            native_point: pt_nat,
            native_value: u.challenges[t][k],
        });
    }
}

/// Read tx `t`'s squeezed challenges into FRESH wires (allocate + bind). Used by
/// the isolated gate; the plural binds its own in-loop wires directly.
#[cfg_attr(not(test), allow(dead_code))]
fn read_duplex_challenges(
    b: &mut FieldR1csBuilder,
    u: &DuplexUnion,
    t: usize,
    base: usize,
    out: &mut Vec<Claim>,
) -> Vec<LinExpr> {
    let wires: Vec<LinExpr> = (0..u.layout.challenges.len())
        .map(|k| LinExpr::from_wire(b.alloc_f128(u.challenges[t][k])))
        .collect();
    bind_duplex_challenges(u, t, base, &wires, out);
    wires
}

/// The `(slot, lane)` where each data lane `k` is absorbed, read off the compiled
/// layout — a class constant used to place each tx's absorb-binding claims.
pub(crate) fn duplex_data_positions(layout: &DuplexLayout) -> Vec<(usize, usize)> {
    let mut pos = vec![(0usize, 0usize); layout.n_data];
    for (slot, ds) in layout.slots.iter().enumerate() {
        for (lane, src) in ds.lanes.iter().enumerate() {
            if let Some(LaneSource::Data(k)) = src {
                pos[*k] = (slot, lane);
            }
        }
    }
    pos
}

// ===========================================================================
// HETEROGENEOUS walk-C union: N DIFFERENT duplex channels per tx, ONE walk.
//
// The homogeneous `build_duplex_union` tiles K copies of ONE channel schedule.
// This variant tiles K transactions each carrying N DIFFERENT channels (distinct
// IVs, distinct op layouts) into ONE data-parallel walk. It is the memory
// optimization that lets the owner-auth KSCHANNL channel and the wallet-PCS
// FRICHANL channel share ONE walk-C (~1.1M rows) instead of two: the substitution
// wiring `raw_j(w) = (1+START(w))·C_j(w−1) + ABS_j(w)·A_j(w) + CONST_j(w)` is
// UNIFORM across the whole slot domain, so as long as the fixed patterns place
// each channel's START / IV / absorb-selector / rate-constant lanes at the right
// slots, ONE `duplex_substitution_terms` relation discharges every channel of
// every tx — and `run_duplex_union_native` / `discharge_duplex_union` (which read
// only the 6 committed columns, the 7 fixed patterns, the refs and s0/s_out, and
// NEVER the layout) work UNCHANGED on the combined [`DuplexUnion`].
//
// Layout — common-S sub-block tiling: sub-channel `i` occupies the power-of-two
// sub-block `[i·S, (i+1)·S)` of every per-tx block, where
// `S = next_pow2(max_i subs[i].slots.len())`; the per-tx period is `N·S` (N padded
// to a power of two with canonical IV-seeded ghost sub-channels). Sub-block `i` of
// tx `t` sits at global offset `t·N·S + i·S`.
//
// Carry reset (THE correctness crux): the combined START pattern has a `1` at
// EVERY sub-channel's slot 0 (`i·S` for all i), so the substitution's
// `(1+START)·C_j(w−1)` term zeroes there — each sub-channel re-seeds its OWN IV and
// does NOT inherit the previous sub-channel's final carry. That is exactly what
// makes the N channels within one tiled block independent (proven by
// `combined_duplex_union_tests::combined_correctness_vs_separate`).
// ===========================================================================

/// One heterogeneous sub-channel of a combined walk-C union: its compiled duplex
/// schedule and its capacity IV. Different sub-channels may have DIFFERENT
/// schedules AND DIFFERENT IVs (e.g. FRICHANL vs KSCHANNL), yet still share ONE
/// data-parallel walk.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone)]
pub(crate) struct SubChannel {
    pub(crate) layout: DuplexLayout,
    pub(crate) iv_flat: [F128; 2],
}

/// The 7 duplex fixed patterns (`start, abs0, abs1, const0..const3`) over the
/// combined per-tx period `N·S`, with sub-channel `i` placed at offset `i·S`.
/// Mirrors `duplex_fixed_patterns` per sub-block: `start[i·S]=1` (the carry reset),
/// the capacity IV on `const2/const3` at `i·S`, and each real slot's absorb
/// selectors / rate constants at `i·S + sl`. Ghost sub-block slots (past a sub's
/// real length) carry START=0 and no constants — they just continue the chain, and
/// `build_duplex_columns` fills the matching continuing-chain tail per sub-block.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn combined_duplex_fixed_patterns(
    subs: &[SubChannel],
    s_log: usize,
) -> Vec<FixedPattern> {
    let s = 1usize << s_log;
    let per_tx = subs.len() * s;
    let block_log = per_tx.trailing_zeros() as usize;
    let mut start = vec![F128::ZERO; per_tx];
    let mut abs: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; per_tx]);
    let mut consts: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; per_tx]);
    for (i, sub) in subs.iter().enumerate() {
        let off = i * s;
        assert!(
            sub.layout.slots.len() <= s,
            "sub schedule exceeds the common S"
        );
        // Carry reset + IV seed at this sub-channel's slot 0.
        start[off] = F128::ONE;
        consts[2][off] = sub.iv_flat[0];
        consts[3][off] = sub.iv_flat[1];
        for (sl, ds) in sub.layout.slots.iter().enumerate() {
            for (j, lane) in ds.lanes.iter().enumerate() {
                match lane {
                    Some(LaneSource::Data(_)) => abs[j][off + sl] = F128::ONE,
                    Some(LaneSource::Const(cv)) => consts[j][off + sl] = flat_of_tower_u128(*cv),
                    None => {}
                }
            }
        }
    }
    let mut out = Vec::with_capacity(3 + STATE_SIZE);
    out.push(FixedPattern::new(block_log, start));
    for pat in abs {
        out.push(FixedPattern::new(block_log, pat));
    }
    for pat in consts {
        out.push(FixedPattern::new(block_log, pat));
    }
    out
}

/// The combined [`DuplexLayout`] over the per-tx period `N·S`: each sub-channel's
/// slots placed at offset `i·S` with Data lane indices RENUMBERED to the flattened
/// `[sub0 data ++ sub1 data ++ ...]` global stream, and challenges concatenated in
/// sub order with slots shifted by `i·S` (matching the per-tx challenge stream). By
/// construction `duplex_data_positions(&combined_duplex_layout(subs, s_log))` ==
/// [`combined_duplex_data_positions`]`(subs, s_log)`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn combined_duplex_layout(subs: &[SubChannel], s_log: usize) -> DuplexLayout {
    let s = 1usize << s_log;
    let per_tx = subs.len() * s;
    let mut slots = vec![
        DuplexSlot {
            lanes: [None, None]
        };
        per_tx
    ];
    let mut challenges = Vec::new();
    let mut data_off = 0usize;
    for (i, sub) in subs.iter().enumerate() {
        let off = i * s;
        for (sl, ds) in sub.layout.slots.iter().enumerate() {
            let lanes = std::array::from_fn(|lane| match ds.lanes[lane] {
                Some(LaneSource::Data(k)) => Some(LaneSource::Data(data_off + k)),
                other => other,
            });
            slots[off + sl] = DuplexSlot { lanes };
        }
        for &(slot, lane) in &sub.layout.challenges {
            challenges.push((off + slot, lane));
        }
        data_off += sub.layout.n_data;
    }
    DuplexLayout {
        slots,
        challenges,
        n_data: data_off,
    }
}

/// Each data lane's `(slot, lane)` in the combined per-tx block, in the flattened
/// `[sub0 data ++ sub1 data ++ ...]` order — sub `i`'s `duplex_data_positions` with
/// slot shifted by `i·S`. The per-tx algebra reads each channel's absorbed data at
/// these positions; agrees with `duplex_data_positions(&combined_duplex_layout(..))`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn combined_duplex_data_positions(
    subs: &[SubChannel],
    s_log: usize,
) -> Vec<(usize, usize)> {
    let s = 1usize << s_log;
    let mut out = Vec::new();
    for (i, sub) in subs.iter().enumerate() {
        let off = i * s;
        for (slot, lane) in duplex_data_positions(&sub.layout) {
            out.push((off + slot, lane));
        }
    }
    out
}

/// Tile `data.len()` transactions, each carrying `subs.len()` DIFFERENT duplex
/// sub-channels, into ONE walk-C domain. `data[t][i]` is sub-channel `i`'s
/// absorbed-data stream for tx `t` (flat, length `subs[i].layout.n_data`).
///
/// The result is a drop-in [`DuplexUnion`]: `run_duplex_union_native` and
/// `discharge_duplex_union` are AGNOSTIC to how many sub-channels a block holds
/// (they walk the 6 committed columns and open each at ONE random point), so ONE
/// carry-selection + ONE walk + ONE substitution discharges every sub-channel of
/// every tx. The per-tx challenge stream `challenges[t]` is the sub-channels'
/// squeezed challenges CONCATENATED in sub order.
///
/// Padding: `N` is padded to a power of two with canonical IV-seeded ghost
/// sub-channels (empty schedules → pure IV chains, no absorbs, no challenges); `K`
/// is padded to a power of two with ghost TILES (zero-data channel blocks). Both
/// pads are valid chains re-seeded by the START pattern — never `perm([0;4])` ghost
/// slots (the duplex substitution's leading carry term is ungated, so every block
/// must be a genuine IV-seeded chain).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_combined_duplex_union(
    subs: &[SubChannel],
    data: &[Vec<Vec<F128>>],
) -> DuplexUnion {
    assert!(!subs.is_empty(), "need at least one sub-channel");
    let n_real = subs.len();
    let n = n_real.next_power_of_two();
    // Common S = smallest power-of-two slot capacity across all sub-channels.
    let s = subs
        .iter()
        .map(|c| c.layout.slots.len())
        .max()
        .unwrap()
        .max(1)
        .next_power_of_two();
    let s_log = s.trailing_zeros() as usize;
    let per_tx = n * s;
    let block_log = per_tx.trailing_zeros() as usize;
    let k = data.len();
    let w_log = (k.max(1) * per_tx).next_power_of_two().trailing_zeros() as usize;
    let p = 1usize << w_log;
    let n_tx_blocks = p / per_tx;

    // Validate the caller's data shape against the real sub-channels.
    for (t, row) in data.iter().enumerate() {
        assert_eq!(
            row.len(),
            n_real,
            "data row {t} width must equal the sub-channel count"
        );
        for (i, stream) in row.iter().enumerate() {
            assert_eq!(stream.len(), subs[i].layout.n_data, "data[{t}][{i}] length");
        }
    }

    // Pad N up to a power of two with canonical ghost sub-channels (an empty
    // schedule seeds a pure zero-IV chain in its S-block — no absorbs, no
    // challenges). For the N=2 wallet use this is a no-op.
    let ghost = SubChannel {
        layout: DuplexLayout {
            slots: Vec::new(),
            challenges: Vec::new(),
            n_data: 0,
        },
        iv_flat: [F128::ZERO, F128::ZERO],
    };
    let subs_padded: Vec<SubChannel> = (0..n)
        .map(|i| {
            if i < n_real {
                subs[i].clone()
            } else {
                ghost.clone()
            }
        })
        .collect();

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges: Vec<Vec<F128>> = Vec::with_capacity(k);

    for blk in 0..n_tx_blocks {
        let mut tx_challenges: Vec<F128> = Vec::new();
        for (i, sub) in subs_padded.iter().enumerate() {
            let zero_data = vec![F128::ZERO; sub.layout.n_data];
            let d: &[F128] = if blk < k && i < n_real {
                &data[blk][i]
            } else {
                &zero_data
            };
            // Each sub-block is an S-slot homogeneous block: slot 0 is
            // IV-seeded, later slots carry, and the tail past the real schedule is
            // the continuing chain fill — copied wholesale into the tiled domain.
            let cols = build_duplex_columns(&sub.layout, sub.iv_flat, d, s_log);
            let off = blk * per_tx + i * s;
            for j in 0..2 {
                committed[j][off..off + s].copy_from_slice(&cols.a[j]);
            }
            for j in 0..STATE_SIZE {
                committed[2 + j][off..off + s].copy_from_slice(&cols.c[j]);
                s0[j][off..off + s].copy_from_slice(&cols.s0[j]);
                s_out[j][off..off + s].copy_from_slice(&cols.s_out[j]);
            }
            if blk < k {
                tx_challenges.extend_from_slice(&cols.challenges);
            }
        }
        if blk < k {
            challenges.push(tx_challenges);
        }
    }

    let fixed = combined_duplex_fixed_patterns(&subs_padded, s_log);
    let layout = combined_duplex_layout(&subs_padded, s_log);
    let refs = duplex_family_refs(0, 0);
    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs,
        layout,
        w_log,
        block_log,
        challenges,
        rec_blocks: Vec::new(),
        rec_refs: Vec::new(),
        rec_challenges: Vec::new(),
    }
}

/// [`build_combined_duplex_union`] with REGION-2 recording blocks — the
/// heterogeneous-sub-channel analogue of
/// [`build_duplex_union_with_recordings`]. Region 1 tiles the K txs'
/// combined sub-channel blocks (its pattern set hi-gated to the region-1
/// dyadic prefix); each recorded discharge transcript rides its own
/// self-aligned dyadic block after it; gaps and the tail are pure carry
/// ghosts. Same pattern/substitution discipline as the homogeneous
/// recordings builder — `run_duplex_union_native` / `discharge_duplex_union`
/// consume the result unchanged.
pub(crate) fn build_combined_duplex_union_with_recordings(
    subs: &[SubChannel],
    data: &[Vec<Vec<F128>>],
    recordings: &[RecordingSpec<'_>],
) -> DuplexUnion {
    assert!(
        !recordings.is_empty(),
        "recording-free combined unions use build_combined_duplex_union"
    );
    assert!(!subs.is_empty(), "need at least one sub-channel");
    let n_real = subs.len();
    let n = n_real.next_power_of_two();
    let s = subs
        .iter()
        .map(|c| c.layout.slots.len())
        .max()
        .unwrap()
        .max(1)
        .next_power_of_two();
    let s_log = s.trailing_zeros() as usize;
    let per_tx = n * s;
    let block_log = per_tx.trailing_zeros() as usize;
    let k = data.len();
    let r1_len = (k.max(1) * per_tx).next_power_of_two();
    let r1_log = r1_len.trailing_zeros() as usize;

    let packing = pack_recordings(r1_len, recordings);
    let w_log = packing.w_log;
    let p = 1usize << w_log;

    for (t, row) in data.iter().enumerate() {
        assert_eq!(
            row.len(),
            n_real,
            "data row {t} width must equal the sub-channel count"
        );
        for (i, stream) in row.iter().enumerate() {
            assert_eq!(stream.len(), subs[i].layout.n_data, "data[{t}][{i}] length");
        }
    }
    let ghost = SubChannel {
        layout: DuplexLayout {
            slots: Vec::new(),
            challenges: Vec::new(),
            n_data: 0,
        },
        iv_flat: [F128::ZERO, F128::ZERO],
    };
    let subs_padded: Vec<SubChannel> = (0..n)
        .map(|i| {
            if i < n_real {
                subs[i].clone()
            } else {
                ghost.clone()
            }
        })
        .collect();

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges: Vec<Vec<F128>> = Vec::with_capacity(k);

    // Region 1: the combined tiling (real tx blocks + zero-data ghost
    // tiles up to the region boundary).
    for blk in 0..r1_len / per_tx {
        let mut tx_challenges: Vec<F128> = Vec::new();
        for (i, sub) in subs_padded.iter().enumerate() {
            let zero_data = vec![F128::ZERO; sub.layout.n_data];
            let d: &[F128] = if blk < k && i < n_real {
                &data[blk][i]
            } else {
                &zero_data
            };
            let cols = build_duplex_columns(&sub.layout, sub.iv_flat, d, s_log);
            let off = blk * per_tx + i * s;
            for j in 0..2 {
                committed[j][off..off + s].copy_from_slice(&cols.a[j]);
            }
            for j in 0..STATE_SIZE {
                committed[2 + j][off..off + s].copy_from_slice(&cols.c[j]);
                s0[j][off..off + s].copy_from_slice(&cols.s0[j]);
                s_out[j][off..off + s].copy_from_slice(&cols.s_out[j]);
            }
            if blk < k {
                tx_challenges.extend_from_slice(&cols.challenges);
            }
        }
        if blk < k {
            challenges.push(tx_challenges);
        }
    }

    let rec_challenges = fill_recording_region(
        &mut committed,
        &mut s0,
        &mut s_out,
        r1_len,
        &packing,
        recordings,
    );

    let mut fixed: Vec<FixedPattern> = combined_duplex_fixed_patterns(&subs_padded, s_log)
        .into_iter()
        .map(|pat| pat.gated(r1_log, rec_hi_bits(0, r1_log, w_log)))
        .collect();
    let rec_refs = gate_recording_patterns(&mut fixed, &packing, recordings);

    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs: duplex_family_refs(0, 0),
        layout: combined_duplex_layout(&subs_padded, s_log),
        w_log,
        block_log,
        challenges,
        rec_blocks: recordings
            .iter()
            .enumerate()
            .map(|(r, rec)| (rec.layout.clone(), packing.offsets[r]))
            .collect(),
        rec_refs,
        rec_challenges,
    }
}

#[cfg(test)]
mod stage1_duplex_union_tests {
    use super::*;
    use noid_ivc_core::deep_chain::schedule::{compile_duplex, TranscriptOp};
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_FRICHANL};

    fn iv_flat() -> [F128; 2] {
        let iv = capacity_iv(TAG_FRICHANL);
        [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
    }

    /// A representative channel schedule exercising every duplex feature: a
    /// three-lane absorb (a full slot + a pending lane), a constant-lane absorb,
    /// a two-challenge squeeze (read + pending + the eager permutation), an
    /// absorb-after-squeeze reset, and a pad-flush squeeze.
    fn channel_ops() -> Vec<TranscriptOp> {
        const TAG: u128 = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10;
        vec![
            TranscriptOp::Absorb(vec![None, None, None]),
            TranscriptOp::Absorb(vec![Some(TAG)]),
            TranscriptOp::Squeeze(2),
            TranscriptOp::Absorb(vec![None, None]),
            TranscriptOp::Absorb(vec![None]),
            TranscriptOp::Squeeze(3),
        ]
    }

    fn tx_data(layout: &DuplexLayout, seed: u64) -> Vec<F128> {
        let mut r = seed;
        (0..layout.n_data)
            .map(|_| {
                r = r.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0x1234_5);
                F128 {
                    lo: r,
                    hi: r.rotate_left(29) ^ 0xA5A5,
                }
            })
            .collect()
    }

    /// The channel union discharges K txs' duplex chains in ONE walk: native
    /// verify (inside `run_duplex_union_native`) + trace satisfiability + the
    /// per-tx challenge wires (read from the carry cells) carry exactly the
    /// native squeezed challenges. Distinct tx data ⇒ distinct challenges, all
    /// recovered from the ONE tiled walk.
    #[test]
    fn duplex_union_native_and_trace() {
        let layout = compile_duplex(&channel_ops());
        let data: Vec<Vec<F128>> = (0..2)
            .map(|t| tx_data(&layout, 0xABCD_0000 + t as u64))
            .collect();
        let u = build_duplex_union(&layout, iv_flat(), &data);
        assert_ne!(
            u.challenges[0], u.challenges[1],
            "per-tx channels squeeze distinct challenges"
        );
        let native = run_duplex_union_native(&u, b"duplex-union-unit");

        let mut b = FieldR1csBuilder::new();
        for col in u.committed.iter() {
            alloc_column_slice(&mut b, col, u.w_log);
        }
        let mut ch = FsChannelTrace::new(&mut b, b"duplex-union-unit");
        let mut claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
        let ch0 = read_duplex_challenges(&mut b, &u, 0, 0, &mut claims);
        let ch1 = read_duplex_challenges(&mut b, &u, 1, 0, &mut claims);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "duplex-union trace unsatisfiable");
        for (k, w) in ch0.iter().enumerate() {
            assert_eq!(w.eval(&z), u.challenges[0][k], "tx0 challenge wire");
        }
        for (k, w) in ch1.iter().enumerate() {
            assert_eq!(w.eval(&z), u.challenges[1][k], "tx1 challenge wire");
        }
        assert!(!claims.is_empty());
    }

    /// TWO-REGION union: region 1 tiles K=2 channel blocks, region 2 hosts two
    /// RECORDED LANECHAL transcripts of different sizes (descending-size dyadic
    /// packing, per-set gated patterns). Honest: satisfiable, every opening
    /// claim true against the committed columns natively, claim count equal to
    /// the single-region discharge (recordings add pins, not claims), and the
    /// build's recording challenges equal the recorder's. Negatives: corrupting
    /// a recording's absorbed-data stream (fed to the union build) breaks the
    /// data-cell pins — the twin's proof wires no longer match the walk-proven
    /// chain — and corrupting an early lane also drags every downstream
    /// challenge pin along; both must be unsatisfiable.
    #[test]
    fn duplex_union_two_region_recording_binding() {
        use noid_ivc_core::lincheck::build_eq_table;

        let layout = compile_duplex(&channel_ops());
        let data: Vec<Vec<F128>> = (0..2)
            .map(|t| tx_data(&layout, 0xBEEF_0000 + t as u64))
            .collect();

        // Two synthetic recorded transcripts of DIFFERENT lengths (the second
        // exercises `sample_f128_vec` and lands in a smaller dyadic block).
        let record = |b: &mut FieldR1csBuilder, domain: &[u8], n_wires: usize, vec_draw: bool| {
            let wires: Vec<LinExpr> = (0..n_wires)
                .map(|i| {
                    let v = F128 {
                        lo: 0x1111 * (i as u64 + 1),
                        hi: 0x77 ^ i as u64,
                    };
                    LinExpr::from_wire(b.alloc_f128(v))
                })
                .collect();
            let mut rec = FsChannelUnionRecorder::new(domain);
            rec.observe_label(b, b"two-region-unit");
            rec.observe_f128_slice(b, &wires);
            let _c1 = rec.sample_f128(b);
            rec.observe_f128(b, &wires[0]);
            if vec_draw {
                let _cv = rec.sample_f128_vec(b, 3);
            }
            rec.observe_f128_slice(b, &wires[..n_wires / 2]);
            let _c2 = rec.sample_f128(b);
            // Trailing absorbs AFTER the last squeeze: corrupting these
            // lanes breaks ONLY their data pins (no downstream
            // challenge). The tail deliberately ends at ODD lane parity
            // (2-lane observe + 3-lane slice = 5 lanes): the last data
            // lane sits alone in a trailing partial-absorb slot, which
            // `compile_duplex` must flush — the real walk discharges end
            // this way, and an unflushed lane would be unpinnable.
            rec.observe_f128(b, &wires[1]);
            rec.observe_f128_slice(b, &wires[..2]);
            rec.finish()
        };

        let run = |corrupt: Option<(usize, usize)>| -> bool {
            let mut b = FieldR1csBuilder::new();
            let rec_a = record(&mut b, b"two-region-rec-a", 24, false);
            let rec_b = record(&mut b, b"two-region-rec-b", 6, true);
            let recs = [&rec_a, &rec_b];
            let mut rec_data: Vec<Vec<F128>> = recs.iter().map(|r| r.data_flat.clone()).collect();
            if let Some((r, lane)) = corrupt {
                rec_data[r][lane] += F128::ONE;
            }
            let rec_iv = FsChannelUnionRecorder::capacity_iv_flat();
            let rec_specs: Vec<RecordingSpec> = recs
                .iter()
                .zip(rec_data.iter())
                .map(|(rc, d)| RecordingSpec {
                    layout: compile_duplex(&rc.ops),
                    iv_flat: rec_iv,
                    data: d,
                })
                .collect();
            let u = build_duplex_union_with_recordings(&layout, iv_flat(), &data, &rec_specs);
            let native = run_duplex_union_native(&u, b"two-region-unit");

            let slices: Vec<WitnessSlice> = u
                .committed
                .iter()
                .map(|c| alloc_column_slice(&mut b, c, u.w_log).0)
                .collect();
            let mut ch = FsChannelTrace::new(&mut b, b"two-region-unit");
            let claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
            // Region-1 challenge pins (the per-tx algebra path) + the
            // recording pins (the plural's region-2 discipline).
            let per_tx = 1usize << u.block_log;
            for tx in 0..2 {
                for (kk, &(slot, lane)) in u.layout.challenges.iter().enumerate() {
                    let w = LinExpr::from_wire(b.alloc_f128(u.challenges[tx][kk]));
                    pin_eq(
                        &mut b,
                        &w,
                        &slot_cell(&slices[u.refs.c[lane]], tx * per_tx + slot),
                    );
                }
            }
            for (r, rc) in recs.iter().enumerate() {
                let (rec_layout, off) = &u.rec_blocks[r];
                assert_eq!(rc.challenge_wires.len(), rec_layout.challenges.len());
                assert_eq!(rc.data_wires.len(), rec_layout.n_data);
                for (kk, &(slot, lane)) in rec_layout.challenges.iter().enumerate() {
                    pin_eq(
                        &mut b,
                        &rc.challenge_wires[kk],
                        &slot_cell(&slices[u.refs.c[lane]], off + slot),
                    );
                }
                for (kk, &(slot, lane)) in duplex_data_positions(rec_layout).iter().enumerate() {
                    pin_eq(
                        &mut b,
                        &rc.data_wires[kk],
                        &slot_cell(&slices[u.refs.a[lane]], off + slot),
                    );
                }
            }

            if corrupt.is_none() {
                // Structure: dyadic packing puts the LARGER recording first
                // and both blocks after region 1; claim count matches the
                // single-region discharge (flatness — recordings are pins).
                let (la, oa) = &u.rec_blocks[0];
                let (lb, ob) = &u.rec_blocks[1];
                let sz = |l: &DuplexLayout| l.slots.len().next_power_of_two();
                assert!(sz(la) >= sz(lb), "recording sizes");
                assert!(
                    *oa >= 2 * per_tx && *ob == oa + sz(la),
                    "descending packing"
                );
                let u1 = build_duplex_union(&layout, iv_flat(), &data);
                let n1 = run_duplex_union_native(&u1, b"two-region-unit");
                let mut b1 = FieldR1csBuilder::new();
                for col in u1.committed.iter() {
                    alloc_column_slice(&mut b1, col, u1.w_log);
                }
                let mut ch1 = FsChannelTrace::new(&mut b1, b"two-region-unit");
                let c1 = discharge_duplex_union(&mut b1, &mut ch1, &u1, &n1, 0);
                assert_eq!(
                    claims.len(),
                    c1.len(),
                    "recording-bearing union claim flatness"
                );
                // Recorder challenges match the union build's chain.
                for (r, rc) in recs.iter().enumerate() {
                    assert_eq!(
                        u.rec_challenges[r].len(),
                        rc.challenge_wires.len(),
                        "recording {r} challenge stream"
                    );
                }
                // Every opening claim is true against the committed columns.
                for c in &claims {
                    let eq = build_eq_table(&c.native_point);
                    let mut acc = F128::ZERO;
                    for (v, e) in u.committed[c.slice].iter().zip(eq.iter()) {
                        acc += *v * *e;
                    }
                    assert_eq!(acc, c.native_value, "claim false on column {}", c.slice);
                }
            }
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        };

        assert!(run(None), "honest two-region union unsatisfiable");
        // rec_a data lanes: 24 (slice) + 1 + 12 (slice) + 1 + 2 (tail) = 40;
        // lane 39 is the odd trailing lane living in the flushed partial slot.
        assert!(
            !run(Some((0, 39))),
            "corrupted trailing recording data slipped through the data pin"
        );
        assert!(
            !run(Some((1, 0))),
            "corrupted early lane slipped through the challenge/data pins"
        );
    }

    /// The channel union discharged through the REAL outer PCS: the 6 committed
    /// columns live as witness slices, the whole claim DAG (selection → walk →
    /// substitution → carry shifts) is replayed in-trace, and every terminal +
    /// every squeezed-challenge read becomes an opening claim against the
    /// committed witness. Flipping the committed carry cell that a challenge is
    /// read from makes exactly that opening claim false — the BaseFold layer
    /// rejects, proving the squeezed challenge is bound to the walk-proven
    /// carry cell (not a value the prover is free to choose).
    #[test]
    fn duplex_union_slot_end_to_end() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec};
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        const OUTER: &[u8] = b"duplex-union-slot-outer";
        let layout = compile_duplex(&channel_ops());
        let k = 2usize;
        let data: Vec<Vec<F128>> = (0..k)
            .map(|t| tx_data(&layout, 0xC0FE_0000 + t as u64))
            .collect();
        let u = build_duplex_union(&layout, iv_flat(), &data);
        let native = run_duplex_union_native(&u, b"duplex-union-slot");
        let w_log = u.w_log;

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = u
            .committed
            .iter()
            .map(|c| alloc_column_slice(&mut b, c, w_log).0)
            .collect();
        let mut ch = FsChannelTrace::new(&mut b, b"duplex-union-slot");
        let mut claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
        for t in 0..k {
            let _ = read_duplex_challenges(&mut b, &u, t, 0, &mut claims);
        }

        let lanes_per_claim = w_log + 1;
        let io_len = claims.len() * lanes_per_claim;
        let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
        let mut io_values = Vec::with_capacity(io_len);
        for c in &claims {
            assert_eq!(c.native_point.len(), w_log, "claim point arity");
            io_values.extend_from_slice(&c.native_point);
            io_values.push(c.native_value);
        }
        let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
        for (ci, c) in claims.iter().enumerate() {
            let base = ci * lanes_per_claim;
            for (k, p) in c.point.iter().enumerate() {
                pin_eq(&mut b, p, &io_wires[base + k]);
            }
            pin_eq(&mut b, &c.value, &io_wires[base + w_log]);
        }
        let spec = PublicIoSpec {
            io_slice,
            io_len,
            claims: claims
                .iter()
                .enumerate()
                .map(|(ci, c)| IoClaimSpec {
                    slice: slices[c.slice],
                    point: ci * lanes_per_claim..ci * lanes_per_claim + w_log,
                    value: ci * lanes_per_claim + w_log,
                })
                .collect(),
        };

        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "honest duplex-union trace unsatisfiable"
        );
        let params = PcsParams {
            m: r1cs.m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (proof, commitment, _) =
            prove_field_with_public_io(&r1cs, &z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut ch_v)
            .expect("the duplex-union slot proof verifies");
        eprintln!(
            "[duplex-union-slot] K={}, rows={} (m={}), opening claims={}",
            k,
            z.len(),
            r1cs.m,
            spec.claims.len()
        );

        // Money negative: flip the committed carry cell that tx 0's first
        // squeezed challenge is read from. The trace stays satisfiable (columns
        // are free wires) but that challenge's opening claim is now false.
        let (chal_slot, chal_lane) = u.layout.challenges[0];
        let col = slices[u.refs.c[chal_lane]];
        let mut bad_z = z.clone();
        bad_z[col.start() + chal_slot] += F128::ONE;
        assert!(r1cs.satisfies(&bad_z), "committed columns are free wires");
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (bad_proof, bad_commitment, _) =
            prove_field_with_public_io(&r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        assert!(
            verify_field_with_public_io(
                &r1cs,
                &bad_commitment,
                &bad_proof,
                &spec,
                &io_values,
                &mut ch_v
            )
            .is_err(),
            "flipping a challenge's carry cell must break its opening claim"
        );
    }

    /// [G] step 4 Stage 2 SOUNDNESS: a RAW-READ committed cell is bound by its
    /// column's single walk opening — no per-cell opening claim needed. This is
    /// the invariant the Stage-2 claim collapse rests on: the walk selection
    /// opens each carry column at ONE random point (Schwartz–Zippel binds every
    /// cell), so the per-tx challenge/absorb reads can drop their per-cell claims
    /// and read the committed cell directly. Here we discharge ONLY the walk
    /// (no `read_duplex_challenges`), raw-read a squeezed challenge straight out
    /// of its carry cell, and show: honest verifies + the raw-read carries the
    /// native challenge value; flipping that carry cell leaves the trace
    /// satisfiable (the cell is unconstrained by the trace — no per-cell claim)
    /// yet breaks the column's selection opening → the PCS rejects. So the
    /// raw-read value is provably the correct squeezed challenge.
    #[test]
    fn duplex_union_raw_read_binding() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec};
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        const OUTER: &[u8] = b"duplex-raw-read-outer";
        let layout = compile_duplex(&channel_ops());
        let data: Vec<Vec<F128>> = (0..2)
            .map(|t| tx_data(&layout, 0x5EED_0000 + t as u64))
            .collect();
        let u = build_duplex_union(&layout, iv_flat(), &data);
        let native = run_duplex_union_native(&u, b"duplex-raw-read");
        let w_log = u.w_log;

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = u
            .committed
            .iter()
            .map(|c| alloc_column_slice(&mut b, c, w_log).0)
            .collect();
        // Discharge ONLY the walk (selection -> walk -> substitution -> shifts).
        // NO per-cell challenge reads: the Stage-2 pattern raw-reads instead.
        let mut ch = FsChannelTrace::new(&mut b, b"duplex-raw-read");
        let claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);

        // RAW-READ tx 0's first squeezed challenge straight out of its carry cell
        // (no fresh wire, no per-cell claim): the cell wire IS the challenge.
        let (chal_slot, chal_lane) = u.layout.challenges[0];
        let c_col = slices[u.refs.c[chal_lane]];
        let chal = LinExpr::from_wire(noid_ivc_core::field_circuit::Wire(
            (c_col.start() + chal_slot) as u32,
        ));

        // Wire the walk claims into the PCS (uniform w_log-arity points).
        let lanes_per = w_log + 1;
        let io_len = claims.len() * lanes_per;
        let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
        let mut io_values = Vec::with_capacity(io_len);
        for c in &claims {
            io_values.extend_from_slice(&c.native_point);
            io_values.push(c.native_value);
        }
        let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
        for (ci, c) in claims.iter().enumerate() {
            let base = ci * lanes_per;
            for (kk, p) in c.point.iter().enumerate() {
                pin_eq(&mut b, p, &io_wires[base + kk]);
            }
            pin_eq(&mut b, &c.value, &io_wires[base + w_log]);
        }
        let spec = PublicIoSpec {
            io_slice,
            io_len,
            claims: claims
                .iter()
                .enumerate()
                .map(|(ci, c)| IoClaimSpec {
                    slice: slices[c.slice],
                    point: ci * lanes_per..ci * lanes_per + w_log,
                    value: ci * lanes_per + w_log,
                })
                .collect(),
        };

        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest raw-read trace unsatisfiable");
        // The raw-read cell carries exactly the native squeezed challenge.
        assert_eq!(
            chal.eval(&z),
            u.challenges[0][0],
            "raw-read == native challenge"
        );
        let params = PcsParams {
            m: r1cs.m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (proof, commitment, _) =
            prove_field_with_public_io(&r1cs, &z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut ch_v)
            .expect("honest raw-read proof verifies");

        // Flip the raw-read carry cell: the trace stays satisfiable (no per-cell
        // claim constrains it) but the column's selection opening is now false.
        let mut bad_z = z.clone();
        bad_z[c_col.start() + chal_slot] += F128::ONE;
        assert!(
            r1cs.satisfies(&bad_z),
            "the raw-read cell is unconstrained by the trace"
        );
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (bad_proof, bad_commitment, _) =
            prove_field_with_public_io(&r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        assert!(
            verify_field_with_public_io(
                &r1cs,
                &bad_commitment,
                &bad_proof,
                &spec,
                &io_values,
                &mut ch_v
            )
            .is_err(),
            "flipping a raw-read carry cell must break the column's walk opening"
        );
    }

    /// Transaction-count independence: doubling K raises the tiled domain by one
    /// bit, so the ONE channel walk gains exactly one sumcheck round —
    /// logarithmic, not the K-fold of K inline channel replays.
    #[test]
    fn duplex_union_walk_is_flat() {
        let layout = compile_duplex(&channel_ops());
        let rounds = |k: usize| {
            let data: Vec<Vec<F128>> = (0..k)
                .map(|t| tx_data(&layout, 0xF1A7_0000 + t as u64))
                .collect();
            let u = build_duplex_union(&layout, iv_flat(), &data);
            run_duplex_union_native(&u, b"flat").walk_proof.layers[0]
                .round_coeffs
                .len()
        };
        let r1 = rounds(1);
        assert_eq!(rounds(2), r1 + 1, "K:1->2 adds one walk round");
        assert_eq!(rounds(4), r1 + 2, "K:1->4 adds two walk rounds");
        assert_eq!(rounds(8), r1 + 3, "K:1->8 adds three walk rounds");
    }
}

/// [G] step 4 — the HETEROGENEOUS duplex-union walk C: K txs, each carrying N
/// DIFFERENT Poseidon2b channels (different IVs, different op layouts), tiled into
/// ONE data-parallel walk and discharged ONCE. This is the memory optimization
/// that lets the owner-auth KSCHANNL and the wallet-PCS FRICHANL channels share
/// ONE walk-C instead of two.
#[cfg(test)]
mod combined_duplex_union_tests {
    use super::*;
    use noid_ivc_core::deep_chain::schedule::TranscriptOp;
    use noid_poseidon2b::native::domain::DomainTag;

    fn iv_flat(tag: DomainTag) -> [F128; 2] {
        let iv = capacity_iv(tag);
        [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
    }

    /// Channel 0 (FRICHANL-shaped): 7 slots, 6 data lanes, 5 squeezed challenges —
    /// a three-lane absorb, a constant-lane absorb, a two-challenge squeeze, an
    /// absorb-after-squeeze reset, and a pad-flush squeeze.
    fn channel0_ops() -> Vec<TranscriptOp> {
        const TAG: u128 = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10;
        vec![
            TranscriptOp::Absorb(vec![None, None, None]),
            TranscriptOp::Absorb(vec![Some(TAG)]),
            TranscriptOp::Squeeze(2),
            TranscriptOp::Absorb(vec![None, None]),
            TranscriptOp::Absorb(vec![None]),
            TranscriptOp::Squeeze(3),
        ]
    }

    /// Channel 1 (KSCHANNL-shaped, deliberately DIFFERENT counts): 4 slots, 3 data
    /// lanes, 3 challenges — a two-lane absorb, a one-challenge squeeze, then an
    /// absorb + pad-flush two-challenge squeeze.
    fn channel1_ops() -> Vec<TranscriptOp> {
        vec![
            TranscriptOp::Absorb(vec![None, None]),
            TranscriptOp::Squeeze(1),
            TranscriptOp::Absorb(vec![None]),
            TranscriptOp::Squeeze(2),
        ]
    }

    /// Channel 2 (a THIRD distinct shape, for the N=3→4 ghost-sub padding test): 3
    /// slots, 4 data lanes, 2 challenges.
    fn channel2_ops() -> Vec<TranscriptOp> {
        vec![
            TranscriptOp::Absorb(vec![None, None, None, None]),
            TranscriptOp::Squeeze(2),
        ]
    }

    fn tx_data(layout: &DuplexLayout, seed: u64) -> Vec<F128> {
        let mut r = seed;
        (0..layout.n_data)
            .map(|_| {
                r = r.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0x1234_5);
                F128 {
                    lo: r,
                    hi: r.rotate_left(29) ^ 0xA5A5,
                }
            })
            .collect()
    }

    fn s_log_of(subs: &[SubChannel]) -> usize {
        subs.iter()
            .map(|c| c.layout.slots.len())
            .max()
            .unwrap()
            .max(1)
            .next_power_of_two()
            .trailing_zeros() as usize
    }

    /// CORRECTNESS vs SEPARATE (the carry-reset proof): building two DIFFERENT
    /// channels into ONE combined union yields, per tx, EXACTLY the challenges each
    /// channel squeezes when tiled alone. That is only possible if each
    /// sub-channel re-seeds its own IV at `i·S` (START=1 there) and does NOT inherit
    /// the previous sub-channel's final carry — i.e. zero cross-channel bleed. Also
    /// checks the data-position map agrees with the combined layout and the
    /// heterogeneous native walk discharges.
    #[test]
    fn combined_correctness_vs_separate() {
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        assert_eq!(
            (ch0.slots.len(), ch0.n_data, ch0.challenges.len()),
            (7, 6, 5)
        );
        assert_eq!(
            (ch1.slots.len(), ch1.n_data, ch1.challenges.len()),
            (4, 3, 3)
        );
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        assert_ne!(iv0, iv1, "the two channels must carry different IVs");
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
        ];
        let k = 2usize;
        let data: Vec<Vec<Vec<F128>>> = (0..k)
            .map(|t| {
                vec![
                    tx_data(&ch0, 0x1000 + t as u64),
                    tx_data(&ch1, 0x2000 + t as u64),
                ]
            })
            .collect();
        let u = build_combined_duplex_union(&subs, &data);

        // Homogeneous unions for each channel ALONE (same per-tx data streams).
        let data0: Vec<Vec<F128>> = (0..k).map(|t| tx_data(&ch0, 0x1000 + t as u64)).collect();
        let data1: Vec<Vec<F128>> = (0..k).map(|t| tx_data(&ch1, 0x2000 + t as u64)).collect();
        let h0 = build_duplex_union(&ch0, iv0, &data0);
        let h1 = build_duplex_union(&ch1, iv1, &data1);

        let (n0, n1) = (ch0.challenges.len(), ch1.challenges.len());
        assert_eq!(u.challenges.len(), k);
        for t in 0..k {
            assert_eq!(
                u.challenges[t].len(),
                n0 + n1,
                "concatenated challenge count"
            );
            assert_eq!(
                &u.challenges[t][0..n0],
                h0.challenges[t].as_slice(),
                "channel 0 squeezes exactly its standalone challenges (no cross-channel bleed)"
            );
            assert_eq!(
                &u.challenges[t][n0..n0 + n1],
                h1.challenges[t].as_slice(),
                "channel 1 squeezes exactly its standalone challenges (no cross-channel bleed)"
            );
        }
        assert_ne!(
            u.challenges[0], u.challenges[1],
            "distinct tx data ⇒ distinct challenges"
        );

        // Data-position self-consistency: the separate helper agrees with reading
        // the combined layout directly (Data indices renumbered to the global
        // flattened stream).
        let s_log = s_log_of(&subs);
        assert_eq!(
            combined_duplex_data_positions(&subs, s_log),
            duplex_data_positions(&u.layout),
            "data positions agree with the combined layout"
        );
        assert_eq!(
            combined_duplex_data_positions(&subs, s_log).len(),
            ch0.n_data + ch1.n_data,
            "one position per real data lane"
        );

        // The heterogeneous walk discharges natively (soundness of the shared DAG).
        let _ = run_duplex_union_native(&u, b"combined-correctness");
    }

    /// GHOST padding: N=3 (padded to 4 with a canonical IV-seeded ghost sub-channel)
    /// AND K=3 (padded to 4 tx-blocks with zero-data ghost tiles) still recovers
    /// each real channel's standalone challenges and discharges natively — the pads
    /// are valid chains, re-seeded by START, not `perm([0;4])` ghost slots.
    #[test]
    fn combined_ghost_padding() {
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        let ch2 = compile_duplex(&channel2_ops());
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        let iv2 = [
            flat_of_tower_u128(0xA5A5_5A5A_1234_5678_9ABC_DEF0_0F1E_2D3C),
            flat_of_tower_u128(0x5A5A_A5A5_8765_4321_0FED_CBA9_C3D2_E1F0),
        ];
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
            SubChannel {
                layout: ch2.clone(),
                iv_flat: iv2,
            },
        ];
        let k = 3usize; // K=3 -> padded to 4 tx-blocks (ghost tile).
        let data: Vec<Vec<Vec<F128>>> = (0..k)
            .map(|t| {
                vec![
                    tx_data(&ch0, 0x11 + t as u64),
                    tx_data(&ch1, 0x22 + t as u64),
                    tx_data(&ch2, 0x33 + t as u64),
                ]
            })
            .collect();
        let u = build_combined_duplex_union(&subs, &data);

        // N padded to 4 → per-tx period = 4·S.
        let s = 1usize << s_log_of(&subs);
        assert_eq!(1usize << u.block_log, 4 * s, "N padded to a power of two");

        let mk = |layout: &DuplexLayout, iv: [F128; 2], base: u64| {
            let d: Vec<Vec<F128>> = (0..k).map(|t| tx_data(layout, base + t as u64)).collect();
            build_duplex_union(layout, iv, &d)
        };
        let h0 = mk(&ch0, iv0, 0x11);
        let h1 = mk(&ch1, iv1, 0x22);
        let h2 = mk(&ch2, iv2, 0x33);
        let (n0, n1, n2) = (
            ch0.challenges.len(),
            ch1.challenges.len(),
            ch2.challenges.len(),
        );
        assert_eq!(
            u.challenges.len(),
            k,
            "K real tx challenge streams (ghost tile excluded)"
        );
        for t in 0..k {
            assert_eq!(u.challenges[t].len(), n0 + n1 + n2);
            assert_eq!(&u.challenges[t][0..n0], h0.challenges[t].as_slice());
            assert_eq!(&u.challenges[t][n0..n0 + n1], h1.challenges[t].as_slice());
            assert_eq!(
                &u.challenges[t][n0 + n1..n0 + n1 + n2],
                h2.challenges[t].as_slice()
            );
        }
        // The padded (ghost sub + ghost tile) domain still discharges natively.
        let _ = run_duplex_union_native(&u, b"combined-ghost");
    }

    /// The carry reset is LOAD-BEARING (the correctness crux, verified — not just
    /// reasoned). First, structurally: START=1 lands EXACTLY at each sub-channel's
    /// boundary `i·S` and the capacity IV is seeded on the const2/const3 lanes there.
    /// Then, behaviourally: removing the START=1 at the SECOND sub-channel's boundary
    /// makes the heterogeneous discharge NO LONGER verify — the substitution wiring
    /// `(1+START)·C(w−1)` then reads the previous channel's final carry instead of
    /// the IV reset the columns actually used, so the terminal claim is false and
    /// `run_duplex_union_native`'s internal verify panics.
    #[test]
    fn carry_reset_is_load_bearing() {
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
        ];
        let data: Vec<Vec<Vec<F128>>> = (0..2)
            .map(|t| {
                vec![
                    tx_data(&ch0, 0x900 + t as u64),
                    tx_data(&ch1, 0xA00 + t as u64),
                ]
            })
            .collect();
        let u = build_combined_duplex_union(&subs, &data);
        let s = 1usize << s_log_of(&subs);

        // Structural: START is ONE exactly at the two sub-channel boundaries {0, S}.
        let start = &u.fixed[u.refs.start];
        let ones: Vec<usize> = start
            .table
            .iter()
            .enumerate()
            .filter(|(_, v)| **v == F128::ONE)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            ones,
            vec![0, s],
            "START resets each sub-channel's carry at i·S"
        );
        // Structural: each boundary seeds its OWN channel's capacity IV.
        assert_eq!(u.fixed[u.refs.consts[2]].table[0], iv0[0]);
        assert_eq!(u.fixed[u.refs.consts[3]].table[0], iv0[1]);
        assert_eq!(u.fixed[u.refs.consts[2]].table[s], iv1[0]);
        assert_eq!(u.fixed[u.refs.consts[3]].table[s], iv1[1]);

        // Honest discharge verifies.
        let _ = run_duplex_union_native(&u, b"carry-reset");

        // Behavioural: remove the reset at sub-channel 1's boundary → the shared
        // discharge must fail (substitution terminal is now false).
        let mut bad = build_combined_duplex_union(&subs, &data);
        bad.fixed[bad.refs.start].table[s] = F128::ZERO;
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silence the expected panic log
        let broke = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run_duplex_union_native(&bad, b"carry-reset");
        }));
        std::panic::set_hook(prev);
        assert!(
            broke.is_err(),
            "removing the carry reset must break the heterogeneous discharge"
        );
    }

    /// ONE discharge binds BOTH channels through the REAL outer PCS. The 6 committed
    /// columns live as witness slices; ONE selection → walk → substitution → shift
    /// discharge opens every A/C column at ONE random point; each tx's squeezed
    /// challenges are read from the carry cells as opening claims. Honest verifies;
    /// flipping a channel-0 carry cell breaks that column's opening (reject), and so
    /// does flipping a channel-1 carry cell — BOTH bound by the ONE walk.
    #[test]
    fn combined_one_discharge_binds_both() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec};
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        const DOM: &[u8] = b"combined-duplex-binds-both";
        const OUTER: &[u8] = b"combined-duplex-binds-both-outer";
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
        ];
        let k = 2usize;
        let data: Vec<Vec<Vec<F128>>> = (0..k)
            .map(|t| {
                vec![
                    tx_data(&ch0, 0xC0FE_0000 + t as u64),
                    tx_data(&ch1, 0xBEEF_0000 + t as u64),
                ]
            })
            .collect();
        let u = build_combined_duplex_union(&subs, &data);
        let native = run_duplex_union_native(&u, DOM);
        let w_log = u.w_log;

        // Build the trace: 6 committed columns as slices, ONE union discharge, and
        // each tx's challenges read from the carry cells.
        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = u
            .committed
            .iter()
            .map(|c| alloc_column_slice(&mut b, c, w_log).0)
            .collect();
        let mut ch = FsChannelTrace::new(&mut b, DOM);
        let mut claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
        for t in 0..k {
            let _ = read_duplex_challenges(&mut b, &u, t, 0, &mut claims);
        }

        // Wire every claim into the outer PCS public IO (uniform w_log-arity points).
        let lanes_per = w_log + 1;
        let io_len = claims.len() * lanes_per;
        let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
        let mut io_values = Vec::with_capacity(io_len);
        for c in &claims {
            assert_eq!(c.native_point.len(), w_log, "claim point arity");
            io_values.extend_from_slice(&c.native_point);
            io_values.push(c.native_value);
        }
        let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
        for (ci, c) in claims.iter().enumerate() {
            let base = ci * lanes_per;
            for (kk, p) in c.point.iter().enumerate() {
                pin_eq(&mut b, p, &io_wires[base + kk]);
            }
            pin_eq(&mut b, &c.value, &io_wires[base + w_log]);
        }
        let spec = PublicIoSpec {
            io_slice,
            io_len,
            claims: claims
                .iter()
                .enumerate()
                .map(|(ci, c)| IoClaimSpec {
                    slice: slices[c.slice],
                    point: ci * lanes_per..ci * lanes_per + w_log,
                    value: ci * lanes_per + w_log,
                })
                .collect(),
        };

        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "honest combined-union trace unsatisfiable"
        );
        assert!(z.len() < (1usize << 21), "wire-count guard");
        let params = PcsParams {
            m: r1cs.m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (proof, commitment, _) =
            prove_field_with_public_io(&r1cs, &z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut ch_v)
            .expect("honest combined-union proof verifies");
        eprintln!(
            "[combined-duplex] N=2 K={k} rows={} (m={}) claims={} — ONE walk binds both channels",
            z.len(),
            r1cs.m,
            spec.claims.len()
        );

        // The two channels' challenge slots (channel 0 first, channel 1 after) —
        // both in tx 0's tiled block.
        let (n0, _n1) = (ch0.challenges.len(), ch1.challenges.len());
        let reject_flip = |slot_lane: (usize, usize), label: &str| {
            let (slot, lane) = slot_lane;
            let col = slices[u.refs.c[lane]];
            let mut bad_z = z.clone();
            bad_z[col.start() + slot] += F128::ONE;
            assert!(
                r1cs.satisfies(&bad_z),
                "committed columns are free wires ({label})"
            );
            let mut ch_p = FsLaneChallenger::new(OUTER);
            let (bad_proof, bad_commitment, _) =
                prove_field_with_public_io(&r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p);
            let mut ch_v = FsLaneChallenger::new(OUTER);
            assert!(
                verify_field_with_public_io(
                    &r1cs,
                    &bad_commitment,
                    &bad_proof,
                    &spec,
                    &io_values,
                    &mut ch_v
                )
                .is_err(),
                "flipping a {label} carry cell must break its opening claim"
            );
        };
        // NEGATIVE A: a channel-0 carry cell (its first squeezed challenge slot).
        reject_flip(u.layout.challenges[0], "channel-0");
        // NEGATIVE B: a channel-1 carry cell (its first squeezed challenge slot,
        // in the i=1 sub-block).
        reject_flip(u.layout.challenges[n0], "channel-1");
    }

    /// FLATNESS: doubling K raises the tiled domain by one bit, so the ONE shared
    /// walk gains exactly ONE sumcheck round — not a second walk. Prints the K=1 vs
    /// K=2 full-trace wire counts (they grow only by the per-tx tiles + one round).
    #[test]
    fn combined_walk_is_flat() {
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
        ];

        // Walk rounds (layer 0 sumcheck rounds) grow by exactly one per K-doubling.
        let walk_rounds = |k: usize| {
            let data: Vec<Vec<Vec<F128>>> = (0..k)
                .map(|t| {
                    vec![
                        tx_data(&ch0, 0xF00D + t as u64),
                        tx_data(&ch1, 0xBA5E + t as u64),
                    ]
                })
                .collect();
            let u = build_combined_duplex_union(&subs, &data);
            run_duplex_union_native(&u, b"combined-flat")
                .walk_proof
                .layers[0]
                .round_coeffs
                .len()
        };
        let r1 = walk_rounds(1);
        assert_eq!(
            walk_rounds(2),
            r1 + 1,
            "K:1->2 adds exactly one shared-walk round"
        );
        assert_eq!(
            walk_rounds(4),
            r1 + 2,
            "K:1->4 adds exactly two shared-walk rounds"
        );

        // Full-trace RAW wire counts (discharge + per-tx challenge reads), taken
        // BEFORE `build()` rounds up to a power of two — the padded `z.len()` would
        // hide the sub-linear growth (both K land in the same 2^m block).
        let trace_wires = |k: usize| -> usize {
            let data: Vec<Vec<Vec<F128>>> = (0..k)
                .map(|t| {
                    vec![
                        tx_data(&ch0, 0xF00D + t as u64),
                        tx_data(&ch1, 0xBA5E + t as u64),
                    ]
                })
                .collect();
            let u = build_combined_duplex_union(&subs, &data);
            let native = run_duplex_union_native(&u, b"combined-flat");
            let mut b = FieldR1csBuilder::new();
            for c in u.committed.iter() {
                alloc_column_slice(&mut b, c, u.w_log);
            }
            let mut ch = FsChannelTrace::new(&mut b, b"combined-flat");
            let mut claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
            for t in 0..k {
                let _ = read_duplex_challenges(&mut b, &u, t, 0, &mut claims);
            }
            b.num_wires()
        };
        let w1 = trace_wires(1);
        let w2 = trace_wires(2);
        eprintln!(
            "[combined-duplex-flat] raw wires K=1: {w1}, K=2: {w2} (Δ={}) — shared walk, NOT a second walk (Δ ≪ w1)",
            w2 - w1
        );
        assert!(
            w2 < 2 * w1,
            "K=2 must NOT be a second walk (sub-linear wire growth)"
        );
        assert!(
            w2 - w1 < w1 / 2,
            "K-doubling grows the trace by ≪ a full walk"
        );
    }
}

#[cfg(test)]
mod owner_auth_region_tests {
    use super::*;
    use noid_core::Block128;
    use noid_gkr::owner_auth::{
        compute_owner_auth_boundary, owner_auth_gkr_channel, prove_owner_auth_killshot,
        OwnerAuthCircuit, OwnerAuthInputs,
    };
    use noid_ivc_core::challenger::FsLaneChallenger;
    use noid_ivc_core::pcs::{self, PcsParams};
    use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec};
    use noid_ivc_core::verifier::verify_field_with_public_io;
    use noid_ivc_prover::field_prover::prove_field_with_public_io;

    use crate::acceptance::trace::owner_auth::build_owner_auth_slot;

    /// Honest fixed-owner fixture. Secrets run the native prover only; no
    /// secret-derived value enters a trace.
    fn fixture(seed: u128) -> (OwnerAuthProofKillShot, OwnerAuthPublicInputs) {
        let circuit = OwnerAuthCircuit::build();
        let spend_secret = [Block128::from(seed + 1000), Block128::from(seed + 2000)];
        let tx_body_hash = [Block128::from(seed + 7), Block128::from(seed + 8)];
        let expected_address = compute_owner_auth_boundary(&circuit, spend_secret, tx_body_hash);
        let public = OwnerAuthPublicInputs::new(tx_body_hash, expected_address);
        let inputs = OwnerAuthInputs::from_parts(&public, spend_secret);
        let mut ch = owner_auth_gkr_channel();
        let (proof, _) = prove_owner_auth_killshot(&circuit, &inputs, &mut ch);
        (proof, public)
    }

    /// `k` honest fixtures of one class (same owner count) with distinct data.
    fn k_fixtures(
        k: usize,
        seed0: u128,
    ) -> (Vec<OwnerAuthProofKillShot>, Vec<OwnerAuthPublicInputs>) {
        let mut proofs = Vec::with_capacity(k);
        let mut publics = Vec::with_capacity(k);
        for t in 0..k {
            let (p, pubx) = fixture(seed0 + (t as u128) * 0x1000);
            proofs.push(p);
            publics.push(pubx);
        }
        (proofs, publics)
    }

    /// Allocate the K trace proofs/inputs, run the region discharge, and thread
    /// every returned committed-column claim through public IO (the
    /// `region_slot_e2e` pattern). Returns the IO spec + values + the claimed
    /// column slices + the walk-C domain `w_log` (for the negative flips). The
    /// caller calls `b.build()`.
    fn region_slot_into_builder(
        b: &mut FieldR1csBuilder,
        proofs: &[OwnerAuthProofKillShot],
        publics: &[OwnerAuthPublicInputs],
    ) -> (PublicIoSpec, Vec<F128>, Vec<WitnessSlice>, usize) {
        let proof_ts: Vec<OwnerAuthProofTrace> = proofs
            .iter()
            .zip(publics.iter())
            .map(|(p, pubx)| OwnerAuthProofTrace::alloc(b, p, pubx.layout))
            .collect();
        let input_ts: Vec<OwnerAuthPublicInputsTrace> = publics
            .iter()
            .map(|pubx| OwnerAuthPublicInputsTrace::alloc(b, pubx))
            .collect();
        let (_obligations, claims, _recording) =
            discharge_owner_auth_killshots_via_region(b, &proof_ts, &input_ts, proofs, publics);
        assert!(
            !claims.is_empty(),
            "region discharge produced no opening claims"
        );

        let w_log = claims[0].point.len();
        let lanes_per = w_log + 1;
        let io_len = claims.len() * lanes_per;
        let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
        let mut io_values = Vec::with_capacity(io_len);
        for c in &claims {
            assert_eq!(c.native_point.len(), w_log, "uniform walk-C claim arity");
            io_values.extend_from_slice(&c.native_point);
            io_values.push(c.native_value);
        }
        let (io_slice, io_wires) = alloc_column_slice(b, &io_values, io_log);
        for (ci, c) in claims.iter().enumerate() {
            let base = ci * lanes_per;
            for (kk, p) in c.point.iter().enumerate() {
                pin_eq(b, p, &io_wires[base + kk]);
            }
            pin_eq(b, &c.value, &io_wires[base + w_log]);
        }
        let claim_slices: Vec<WitnessSlice> = claims.iter().map(|c| c.slice).collect();
        let spec = PublicIoSpec {
            io_slice,
            io_len,
            claims: claims
                .iter()
                .enumerate()
                .map(|(ci, c)| IoClaimSpec {
                    slice: c.slice,
                    point: ci * lanes_per..ci * lanes_per + w_log,
                    value: ci * lanes_per + w_log,
                })
                .collect(),
        };
        (spec, io_values, claim_slices, w_log)
    }

    /// K=1 parity: the region discharge produces the SAME `PendingAuthPcsObligation`
    /// (reduced `r_B` / `b_final` / cap lanes) as the inline
    /// `verify_owner_auth_killshot_trace` (via `build_owner_auth_slot`), and the
    /// combined trace is satisfiable.
    #[test]
    fn owner_auth_region_parity() {
        let (proof, public) = fixture(0xA3);
        let mut b = FieldR1csBuilder::new();

        // Inline obligation (the canonical per-tx replay).
        let (_inputs_inline, obligation_inline) = build_owner_auth_slot(&mut b, &proof, &public);

        // Region obligation on freshly-allocated trace proof/inputs.
        let inputs_t = OwnerAuthPublicInputsTrace::alloc(&mut b, &public);
        let proof_t = OwnerAuthProofTrace::alloc(&mut b, &proof, public.layout);
        let (obligations_region, claims, _recording) = discharge_owner_auth_killshots_via_region(
            &mut b,
            std::slice::from_ref(&proof_t),
            std::slice::from_ref(&inputs_t),
            std::slice::from_ref(&proof),
            std::slice::from_ref(&public),
        );
        assert_eq!(obligations_region.len(), 1);
        assert!(!claims.is_empty());
        let obligation_region = &obligations_region[0];

        let nw = b.num_wires();
        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "owner-auth region parity trace unsatisfiable"
        );

        // Same reduced (r_B, b_final) and cap lanes as the inline twin.
        assert_eq!(obligation_region.num_vars, obligation_inline.num_vars);
        assert_eq!(
            obligation_region.reduction.point.len(),
            obligation_inline.reduction.point.len()
        );
        for (pr, pi) in obligation_region
            .reduction
            .point
            .iter()
            .zip(obligation_inline.reduction.point.iter())
        {
            assert_eq!(pr.eval(&z), pi.eval(&z), "r_B mismatch inline vs region");
        }
        assert_eq!(
            obligation_region.reduction.value.eval(&z),
            obligation_inline.reduction.value.eval(&z),
            "b_final mismatch inline vs region"
        );
        assert_eq!(
            obligation_region.commitment_cap_lanes.len(),
            obligation_inline.commitment_cap_lanes.len()
        );
        for (lr, li) in obligation_region
            .commitment_cap_lanes
            .iter()
            .zip(obligation_inline.commitment_cap_lanes.iter())
        {
            assert_eq!(lr[0].eval(&z), li[0].eval(&z), "cap lane 0");
            assert_eq!(lr[1].eval(&z), li[1].eval(&z), "cap lane 1");
        }
        eprintln!(
            "[owner-auth-region] parity nv={} wires={} (inline+region combined) claims={}",
            OWNER_AUTH_NUM_VARS,
            nw,
            claims.len()
        );
    }

    /// K=1 discharge through the REAL outer PCS: the walk-C committed columns
    /// live as witness slices, every terminal claim becomes an opening claim, and
    /// an honest slot verifies. Money negative: flipping a claimed committed cell
    /// either makes the trace unsatisfiable (if pinned to an algebra wire) or
    /// breaks the column's walk opening → BaseFold rejects.
    #[test]
    fn owner_auth_region_slot_e2e() {
        const OUTER: &[u8] = b"owner-auth-region-slot-outer";
        let (proof, public) = fixture(0x0E2E);
        let mut b = FieldR1csBuilder::new();
        let (spec, io_values, claim_slices, _w_log) = region_slot_into_builder(
            &mut b,
            std::slice::from_ref(&proof),
            std::slice::from_ref(&public),
        );
        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "honest owner-auth region slot unsatisfiable"
        );
        assert!(
            r1cs.m < 22,
            "gate guard: keep the region slot well under 2^22 rows"
        );

        let params = PcsParams {
            m: r1cs.m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (pcs_proof, commitment, _) =
            prove_field_with_public_io(&r1cs, &z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        verify_field_with_public_io(&r1cs, &commitment, &pcs_proof, &spec, &io_values, &mut ch_v)
            .expect("honest owner-auth region slot verifies");
        eprintln!(
            "[owner-auth-region] slot nv={} rows={} (m={}) claims={}",
            OWNER_AUTH_NUM_VARS,
            z.len(),
            r1cs.m,
            spec.claims.len()
        );

        // Money negative: flip the first cell of a claimed committed column.
        let cell = claim_slices[0].start();
        let mut bad_z = z.clone();
        bad_z[cell] += F128::ONE;
        if r1cs.satisfies(&bad_z) {
            // A free (unpinned) cell: the column's walk opening must break.
            let mut ch_p = FsLaneChallenger::new(OUTER);
            let (bad_proof, bad_commitment, _) =
                prove_field_with_public_io(&r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p);
            let mut ch_v = FsLaneChallenger::new(OUTER);
            assert!(
                verify_field_with_public_io(
                    &r1cs,
                    &bad_commitment,
                    &bad_proof,
                    &spec,
                    &io_values,
                    &mut ch_v
                )
                .is_err(),
                "flipping a free committed cell must break its walk opening → PCS reject"
            );
            eprintln!("[owner-auth-region] negative: free-cell flip → PCS reject");
        } else {
            // A pinned cell: no valid witness exists → the R1CS catches it.
            eprintln!("[owner-auth-region] negative: pinned-cell flip → unsatisfiable");
        }
    }

    /// K=2 flatness: two txs in ONE builder discharge on ONE shared walk C. The
    /// walk-round count grows by exactly one per doubling (logarithmic, not a
    /// second walk); the total wire count is strictly sub-linear in K. Honest
    /// K=2 verifies; tampering a committed cell in tx 1's block is rejected.
    #[test]
    fn owner_auth_region_flat() {
        const OUTER: &[u8] = b"owner-auth-region-flat-outer";

        // --- Actual (unpadded) wire counts @K=1 vs @K=2 (the walk-C discharge is
        // shared). `z.len()` is the PCS-padded 2^m and would hide the delta, so we
        // read `num_wires()` before building.
        let (p1, u1) = k_fixtures(1, 0xF1A7);
        let mut b1 = FieldR1csBuilder::new();
        let _ = region_slot_into_builder(&mut b1, &p1, &u1);
        let w1 = b1.num_wires();
        let (r1cs1, z1) = b1.build();
        assert!(r1cs1.satisfies(&z1), "K=1 region slot unsatisfiable");

        let (p2, u2) = k_fixtures(2, 0xF1A7);
        let mut b2 = FieldR1csBuilder::new();
        let (spec2, io2, slices2, w_log2) = region_slot_into_builder(&mut b2, &p2, &u2);
        let w2 = b2.num_wires();
        let (r1cs2, z2) = b2.build();
        assert!(r1cs2.satisfies(&z2), "K=2 region slot unsatisfiable");

        eprintln!(
            "[owner-auth-region] flat: wires K=1={} K=2={} delta={} (K=1 total={})",
            w1,
            w2,
            w2 - w1,
            w1
        );
        // The 2nd tx costs strictly LESS than the whole first-tx cost, because the
        // dominant walk-C discharge (the 66-layer permutation walk, ~1M rows) is
        // done ONCE and amortized — it is NOT a second walk.
        assert!(
            w2 - w1 < w1,
            "K:1->2 delta {} must be below the K=1 total {} (walk-C shared)",
            w2 - w1,
            w1
        );

        // --- Walk-round flatness (native, exact): K doubling adds one sumcheck
        // round to the ONE shared duplex walk.
        let rounds = |k: usize| -> usize {
            let (pp, uu) = k_fixtures(k, 0xBEEF);
            let chan_layout = compile_duplex(&owner_auth_channel_schedule(&pp[0], &uu[0]).ops);
            let iv = {
                let iv = capacity_iv(TAG_KSCHANNL);
                [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
            };
            let streams: Vec<Vec<F128>> = pp
                .iter()
                .zip(&uu)
                .map(|(p, u)| owner_auth_channel_schedule(p, u).data_flat)
                .collect();
            let u_c = build_duplex_union(&chan_layout, iv, &streams);
            run_duplex_union_native(&u_c, OWNER_AUTH_DOMAIN_C)
                .walk_proof
                .layers[0]
                .round_coeffs
                .len()
        };
        let r1 = rounds(1);
        assert_eq!(rounds(2), r1 + 1, "K:1->2 adds exactly one walk round");
        assert_eq!(rounds(4), r1 + 2, "K:1->4 adds exactly two walk rounds");

        // --- K=2 honest PCS + a tx-1 tampering negative.
        let params = PcsParams {
            m: r1cs2.m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (pcs_proof, commitment, _) =
            prove_field_with_public_io(&r1cs2, &z2, &params, &spec2, &io2, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        verify_field_with_public_io(&r1cs2, &commitment, &pcs_proof, &spec2, &io2, &mut ch_v)
            .expect("honest K=2 region slot verifies");

        // Tamper a committed cell in tx 1's block (the second half of the tiled
        // walk-C domain): caught by unsatisfiability (pinned) or a broken opening.
        let p_dom = 1usize << w_log2;
        let cell = slices2[0].start() + p_dom / 2;
        let mut bad_z = z2.clone();
        bad_z[cell] += F128::ONE;
        if r1cs2.satisfies(&bad_z) {
            let mut ch_p = FsLaneChallenger::new(OUTER);
            let (bad_proof, bad_commitment, _) =
                prove_field_with_public_io(&r1cs2, &bad_z, &params, &spec2, &io2, &mut ch_p);
            let mut ch_v = FsLaneChallenger::new(OUTER);
            assert!(
                verify_field_with_public_io(
                    &r1cs2,
                    &bad_commitment,
                    &bad_proof,
                    &spec2,
                    &io2,
                    &mut ch_v
                )
                .is_err(),
                "flipping a tx-1 committed cell must be rejected"
            );
            eprintln!("[owner-auth-region] K=2 negative: tx-1 free-cell flip → PCS reject");
        } else {
            eprintln!("[owner-auth-region] K=2 negative: tx-1 pinned-cell flip → unsatisfiable");
        }
    }
}
