// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! [G] item 5b — the COMPLETE wallet-capsule mixed-opening AUTHENTICATION
//! discharged IN-TRACE via region families in ONE builder, as a reusable src
//! function ([`discharge_auth_pcs_obligation_via_region`]).
//!
//! This is the region twin of the inline
//! [`super::auth_pcs::discharge_auth_pcs_obligation`]: given the same
//! [`PendingAuthPcsObligation`] the owner-auth slot produced and the native
//! [`AuthMleOpeningProof`], it replays `verify_mixed_opening` over region
//! columns (source_tree + source-leaf + high-pair leaf families + the three
//! Merkle-authentication legs 3i / SB6 / SB8 + the SB7->SB9 fold chain + the
//! FRI fold-join), pinning every reduction terminal inline and collecting every
//! committed-column opening claim as a [`RegionPcsClaim`]. Unlike the inline fn
//! (which self-closes in R1CS), the region discharge produces committed-column
//! opening claims that the CALLER threads through the link's public IO — this fn
//! RETURNS them and does NOT build the public IO / prove.
//!
//! ## Structure — TWO union walks in ONE builder (memory)
//! A single deep-chain walk is ~1M rows; discharging every leg's leaf-walk AND
//! Merkle-walk as SEPARATE walks OOMs (region prover memory note). The
//! memory-safe assembly uses exactly TWO union walks, both in the SAME builder:
//!   - **walk A (leaf-union)**: source_tree (SB1.2) + SB6 source-leaf + SB8
//!     high-pair leaf families under ONE carry-selection + ONE walk + ONE
//!     unioned substitution; it opens each leaf tile's digest to a wire.
//!   - **walk B (merkle-union)**: the 3i FRI pair-leaf PLUS the three Merkle
//!     legs (3i / SB6-to-cap / SB8), a heterogeneous union under ONE
//!     carry-selection + ONE walk + ONE unioned substitution.
//! Walk A's per-tile leaf-digest wires feed walk B's SB6 / SB8 Merkle
//! `entry_wires`; walk B's pair-leaf digest wires feed the 3i Merkle entries —
//! all SHARED builder wires, never a public constant.
//!
//! ## Authentication-root TRANSCRIPT binding (the step-2c soundness addition)
//! The one obligation the proven gate deferred: each Merkle-auth root must be
//! bound to the Fiat-Shamir-OBSERVED root wire, not a fresh alloc, so a prover
//! cannot draw honest queries from the observed root yet authenticate fabricated
//! answers against a root chosen AFTER the query positions are known. Here every
//! Merkle leg's per-path recomputed-root cell is `pin_eq`'d to the observed
//! digest wire that seeded the query draws:
//!   - 3i FRI leg (round r): the `fri_roots_w[r]` digest wire, observed via
//!     `observe_vector_commitment` inside the FRI sumcheck BEFORE the FRI query
//!     draw (all paths of a round share it).
//!   - SB8 leg (layer i): the `folded_roots_w[i]` digest wire, absorbed in the
//!     SB2 loop BEFORE the source query draw.
//!   - SB6 leg (to-cap): the SOURCE-CAP lane of the ABSORBED
//!     `commitment_cap_lanes` — `commitment_cap_lanes[(1<<MERKLE_CAP_DEPTH) +
//!     (leaf >> walk_depth)]`, absorbed by `absorb_cap` at the transcript start.
//! Because the recomputed root (in the Merkle family's C column at the root
//! slot, its whole MLE bound by the walk's random-point opening) is pinned ==
//! this observed wire, the walk-authenticated root IS the transcript-seeded root
//! — the auth is FS-bound, and the pin is an R1CS row (not an IO claim) so the
//! binding stays flat in tx count.
//!
//! ## Scope (matches the proven gate `region_source_binding_full_e2e`)
//! The 3i FRI leg + FRI fold-join authenticate round 0 (n_rounds == 1 at the
//! wallet nv range validated by the unit gate). `RegionDischargeParams` exposes
//! the two documented memory reductions — `nq` (queries discharged; the channel
//! is still driven with the full `COMPACT_NUM_QUERIES`) and `sb8_auth_layers`
//! (deepest high-fold layers authenticated) — so the link can pass the full
//! values; the leaf fold chain in walk A still spans ALL `tau-1` layers to close
//! SB9 regardless.

use noid_core::hardware::flat_to_tower_u128;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::code::{Code, LOG_RATE};
use noid_fri::merkle::VectorCommitment;
use noid_fri::Channel;
use noid_fri_binius::compact_fri::{
    compute_round_depth, expand_batched_merkle_proof, expand_batched_merkle_proof_to_cap,
    gen_compact_queries, BatchedMerkleProof,
};
use noid_fri_binius::interleaved_commit::{
    source_cap_depth, source_cap_from_commitment_cap, source_leaf_hash, source_tree_depth,
    CommitmentHashBackend,
};
use noid_fri_binius::mixed_open::{
    high_pair_leaf_hash_for_trace, high_pair_leaf_index, high_pair_tree_depth, MIXED_OPEN_TAG,
    MIXED_SOURCE_BINDING_TAG,
};
use noid_fri_binius::{COMPACT_NUM_QUERIES, COMPACT_TAU, MERKLE_CAP_DEPTH};
use noid_gkr::auth_pcs::AuthMleOpeningProof;
use noid_gkr::owner_auth::{OwnerAuthProofKillShot, OwnerAuthPublicInputs};
use noid_poseidon2b::hasher::CryptographicHasher;
use noid_poseidon2b::native::domain::{
    capacity_iv, DomainTag, TAG_EXSTNOD, TAG_FRICHANL, TAG_KSCHANNL, TAG_RGDNODE,
};
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_poseidon2b::Poseidon2bSponge;

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::flat_mds;
use noid_ivc_core::deep_chain::leaf_hash::{
    build_high_pair_leaf_columns, build_pair_leaf_columns, build_source_leaf_columns,
    build_sponge_leaf_columns, high_pair_leaf_chain, pair_leaf_refs, pair_leaf_substitution_terms,
    slot_leaf_iv_flat, slot_leaf_pad_flat, source_leaf_fixed_patterns, source_leaf_refs,
    source_leaf_substitution_terms, sponge_leaf_fixed_patterns, sponge_leaf_substitution_terms,
    PairLeafRefs, SourceLeafChain, SourceLeafColumns, SourceLeafRefs, SpongeLeafRefs,
    SPONGE_LEAF_DIGEST_SLOT, SPONGE_LEAF_SLOTS,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2,
    window_discharge_point, ColRef, ColumnRelationProof, FixedPattern, RelationColumns,
    RelationTerm, ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::schedule::{
    build_duplex_columns, build_merkle_path_columns, carry_selection_terms, compile_duplex,
    duplex_family_refs, duplex_fixed_patterns, duplex_substitution_terms, flat_of_tower_u128,
    merkle_booleanity_terms, merkle_fixed_patterns, merkle_substitution_terms, DuplexFamilyRefs,
    DuplexLayout, DuplexSlot, LaneSource, MerkleFamilyRefs, MerklePathColumns, MerklePathFamily,
    MerklePathWitness,
};
use noid_ivc_core::deep_chain::source_tree::{
    build_source_code_columns, build_source_tree_columns, compress_iv_flat,
    source_tree_exposure_terms, source_tree_fixed_patterns, source_tree_substitution_terms,
    SourceTree, SourceTreeRefs,
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
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr, Wire};
use noid_ivc_core::public_io::WitnessSlice;

use super::deep_chain::{
    verify_column_relation_trace, verify_deep_chain_walk_trace, verify_shift_discharge_trace,
    ColumnRelationProofTrace, DeepChainWalkProofTrace, LaneClaimGroupTrace, RelationTermTrace,
    ShiftDischargeProofTrace,
};
use super::exact_state::ExactStateRegionData;
use super::fri_pcs::{
    alloc_digest, code_new_trace, compact_queries_from_squeezes_with_bits, fold_trace_bits,
    mle_evaluate_small_trace,
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
use crate::acceptance::region::{capsule_pcs_channel_schedule, owner_auth_channel_schedule};

// FS domains for the two region walks (self-contained sub-protocols; the
// soundness of the discharge lives in the committed-column opening claims the
// caller threads through the outer PCS, not in these transcripts).
const DOMAIN: &[u8] = b"source-binding-full-leaf-union";
const DOMAIN_B: &[u8] = b"source-binding-full-merkle-union";
const DOMAIN_C: &[u8] = b"source-binding-full-duplex-union";

// Meta committed column order (all length P):
//   CODE0=0, CODE1=1, KID0=2, KID1=3, IN0=4, IN1=5, C0=6..C3=9.
const CODE0: usize = 0;
const KID0: usize = 2;
const IN0: usize = 4;
const C0: usize = 6;
const N_COMMITTED: usize = 10;

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

/// The two documented memory reductions of the region discharge, exposed so the
/// unit gate can keep them small while the link passes the full values.
#[derive(Clone, Copy, Debug)]
pub struct RegionDischargeParams {
    /// Number of distinct SOURCE-side queries AUTHENTICATED per leg (a subset
    /// of `COMPACT_NUM_QUERIES`; the channel is still driven with the full
    /// count, so the transcript is faithful). The FRI-side legs (round-0
    /// pair leaves + the 3i Merkle leg + the fold-join) saturate at the
    /// folded-domain query count the channel actually draws
    /// (`min(COMPACT_NUM_QUERIES, 2^(n_rounds + LOG_RATE))`), so passing the
    /// full `COMPACT_NUM_QUERIES` authenticates EVERY query on both sides —
    /// the production setting.
    pub nq: usize,
    /// Number of DEEPEST SB8 high-fold layers authenticated. The leaf fold chain
    /// in walk A always spans ALL `tau-1` layers to close SB9 regardless.
    pub sb8_auth_layers: usize,
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
/// state paths (TAG_EXSTNOD) and guard paths (TAG_RGDNODE) join walk B as two
/// more Merkle legs with their own tree IVs. Block-level entries are chunked
/// `ceil(len/K)` per tx block (contiguous, canonical-ghost-filled), so the
/// layout stays a deterministic function of (input lengths, K, depths) —
/// class-fixed. Leaf digests pin to the slot-leaf `expected_leaf` statement
/// wires which double as the state leg's entry wires (the leaf↔path closure),
/// and each leg root pins to the composite-root statement wires (path↔root).
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
) -> Vec<RegionPcsClaim> {
    assert_eq!(obligations.len(), natives.len(), "one native proof per obligation");
    assert!(!obligations.is_empty(), "at least one obligation");
    // The K txs' families tile ONE walk A (source tree + leaves) + ONE walk B
    // (pair-leaf + merkle legs) + ONE walk C (FRICHANL channels) at common-period
    // offsets, with K per-tree source-tree exposures and a per-tx algebra loop.
    let k = obligations.len();

    // ===================================================================
    // Class-level shapes (identical across the block's txs; the class is
    // shape-fixed, so tx 0 defines the whole layout).
    // ===================================================================
    let num_vars = obligations[0].num_vars;
    let nq = params.nq;
    let log_n = natives[0].commitment.log_rows;
    let tau = COMPACT_TAU.min(log_n);
    let n_rounds = log_n - tau;
    // The FRI-side legs (round-0 pair leaves, the 3i Merkle leg, the
    // fold-join) SATURATE at the folded domain: the channel only draws
    // `min(COMPACT_NUM_QUERIES, 2^(n_rounds + LOG_RATE))` FRI queries (at the
    // wallet shape that is 8 — every position of the folded codeword), so the
    // full-production `nq = COMPACT_NUM_QUERIES` authenticates ALL of them.
    let nq_fri = nq.min(COMPACT_NUM_QUERIES.min(1usize << (n_rounds + LOG_RATE)));
    let ntt = AdditiveNTT::<Block128>::new(num_vars + LOG_RATE);
    let leaf_chain = SourceLeafChain { n_cols: 1 };
    let hp_chain = high_pair_leaf_chain();
    let leaf_stride = leaf_chain.stride();
    let leaf_stride_log = leaf_stride.trailing_zeros() as usize;
    assert_eq!(leaf_stride, hp_chain.stride());
    let n_layers = tau.saturating_sub(1);
    let n_leaf_families = 1 + n_layers;
    let leaf_family_slots = nq * leaf_stride;
    let tree = SourceTree { leaf_log: n_rounds + 1 };
    let st_wlog = tree.slots_log();
    let st_slots = tree.n_slots();
    let l = tree.leaf_count();

    // Walk-A domain: `[tx_hi | within-tx block]`. Every tx's source tree +
    // leaf families occupy one power-of-two block; the K blocks tile the domain,
    // so common-period patterns (period = the block) cover every tx.
    //
    // Exact-state extension: the block's `2T` slot-leaf sponge tiles ride the
    // SAME walk A after the wallet leaf families, distributed across the K tx
    // blocks in contiguous chunks of `es_leaf_cap = ceil(2T/K)` tiles each
    // (shortfall = canonical ghost sponge leaves) — the layout stays a pure
    // function of (2T, K).
    let es_leaf_base = st_slots + n_leaf_families * leaf_family_slots; // within a tx block
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
    let leaf_base = |f: usize| st_slots + f * leaf_family_slots; // within a tx block

    // Walk-B leg layout (class constant): the 3i pair-leaf at `[0, nq_fri)`, then the
    // legs at `meta_bases[f]`, all within a per-tx block.
    let round = 0usize;
    let sb6_walk_depth = source_tree_depth(log_n) - source_cap_depth(log_n);
    assert!(params.sb8_auth_layers <= n_layers, "sb8_auth_layers exceeds available fold layers");
    let sb8_auth_layers: Vec<usize> = (0..params.sb8_auth_layers).map(|kk| n_layers - 1 - kk).collect();
    let mut leg_depths: Vec<usize> = vec![compute_round_depth(n_rounds, round), sb6_walk_depth];
    for &layer in &sb8_auth_layers {
        leg_depths.push(high_pair_tree_depth(log_n - 1 - layer));
    }
    // Per-leg per-tx-block path capacity and per-leg tree IV. The wallet legs
    // open `nq` paths per tx on TAG_COMPRESS trees; the exact-state legs open
    // the block's chunked state/guard paths on their consensus-tagged trees
    // (the IV is a PER-LEG pattern parameter, so heterogeneous tags coexist
    // in ONE walk B).
    let n_wallet_legs = leg_depths.len();
    let mut leg_caps: Vec<usize> = vec![nq; n_wallet_legs];
    // Leg 0 (the 3i FRI round leg) opens the FRI-side queries — saturated.
    leg_caps[0] = nq_fri;
    let mut leg_ivs: Vec<[F128; 2]> = vec![compress_iv_flat(); n_wallet_legs];
    let es_state_leg = leg_depths.len();
    let mut es_guard_leg = usize::MAX;
    if let Some(e) = es {
        leg_depths.push(e.d_state);
        leg_caps.push(e.paths.len().div_ceil(k));
        leg_ivs.push(iv_flat_of_tag(TAG_EXSTNOD));
        if let Some(g) = &e.guard {
            es_guard_leg = leg_depths.len();
            leg_depths.push(g.depth);
            leg_caps.push(2usize.div_ceil(k));
            leg_ivs.push(iv_flat_of_tag(TAG_RGDNODE));
        }
    }
    // Tx-root paths: one TAG_COMPRESS leg (the same tree hash as the wallet
    // legs), one path per user tx chunked across the tx blocks.
    let txr_leg = leg_depths.len();
    if let Some(t) = txr {
        assert!(!t.paths.is_empty(), "tx-root region handoff without paths");
        leg_depths.push(t.depth);
        leg_caps.push(t.paths.len().div_ceil(k));
        leg_ivs.push(compress_iv_flat());
    }
    let n_legs = leg_depths.len();
    let mut meta_bases = Vec::with_capacity(n_legs);
    let mut acc = nq_fri;
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
    // (zero outside its own slots), and the only cross-boundary shifted reads
    // (`c_sh` at path-start slots) are cancelled by the START patterns — so
    // ALL legs share ONE physical {E0,E1,SIB0,SIB1,D} column set at [6..11)
    // next to the shared pair-IN [0..2) and C0..C3 [2..6). Committed lanes
    // per leg were the production-shape wall (6 + 5·n_legs columns × the
    // k-tiled domain); the shared set is 11 columns regardless of leg count.
    let n_committed_b = 6 + 5;
    let region_pair = 0usize;
    let pair_refs = pair_leaf_refs(0);
    let iv_b = compress_iv_flat();
    let hasher = Poseidon2bSponge::new();

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
            cb[2 + j][slot] = ghbo[j];
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
    // Tiled source-tree exposure: each tx appends its `kid_lo` (2^(st_wlog-1)) and
    // full C (2^st_wlog) into these 4 columns; ONE sumcheck after the loop
    // discharges every tree (`Window(C,1,1)` tiles since C's period is 2× KID's),
    // re-pointing 4 terminal claims into walk-A — flat (O(1)) in tx count. Requires
    // a power-of-two obligation count so the tiled tx bits align with walk-A's (the
    // discharge pads a tier's real txs to next_pow2 with ghost obligations).
    assert!(
        k.is_power_of_two(),
        "wallet-PCS region discharge expects a power-of-two obligation count \
         (pad the tier's real txs with ghost obligations); got {k}"
    );
    let mut expo_kid0: Vec<F128> = Vec::new();
    let mut expo_kid1: Vec<F128> = Vec::new();
    let mut expo_c0: Vec<F128> = Vec::new();
    let mut expo_c1: Vec<F128> = Vec::new();
    // Tiled SPINE-tree exposure: every instance (real + ghost, block-major)
    // appends its KID low half (2L cells) and full C (4L cells); ONE gated
    // sumcheck after the loop discharges every spine tree, re-pointing 4
    // terminal claims into walk A — flat (O(1)) in tx count.
    let mut spine_expo_kid0: Vec<F128> = Vec::new();
    let mut spine_expo_kid1: Vec<F128> = Vec::new();
    let mut spine_expo_c0: Vec<F128> = Vec::new();
    let mut spine_expo_c1: Vec<F128> = Vec::new();
    // Per-leg-type walk-B accumulators (each grows to K*nq across the loop).
    let mut acc_committed_roots: Vec<Vec<[F128; 2]>> = vec![Vec::new(); n_legs];
    let mut acc_recomputed_roots: Vec<Vec<[F128; 2]>> = vec![Vec::new(); n_legs];
    let mut acc_entry_wires: Vec<Vec<[LinExpr; 2]>> = vec![Vec::new(); n_legs];
    let mut acc_root_wires: Vec<Vec<[LinExpr; 2]>> = vec![Vec::new(); n_legs];
    let mut acc_path_slots: Vec<Vec<usize>> = vec![Vec::new(); n_legs];
    let mut acc_pair_map: Vec<usize> = Vec::new(); // leg 0 (3i): path -> pair index
    let mut pair_digests: Vec<[F128; 2]> = Vec::new();
    let mut pair_slots: Vec<usize> = Vec::new();
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
    let chan_layout = compile_duplex(&capsule_pcs_channel_schedule(&natives[0], num_vars, &point0, COMPACT_NUM_QUERIES).ops);
    let chan_data_positions = duplex_data_positions(&chan_layout);
    let per_tx_block_c = chan_layout.slots.len().next_power_of_two();
    let block_log_c = per_tx_block_c.trailing_zeros() as usize;
    let iv_c = {
        let iv = capacity_iv(TAG_FRICHANL);
        [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
    };
    let n_source_q = COMPACT_NUM_QUERIES.min(1usize << (num_vars + LOG_RATE));
    let n_fri_q = COMPACT_NUM_QUERIES.min(1usize << (n_rounds + LOG_RATE));
    let mut chan_data_streams: Vec<Vec<F128>> = Vec::with_capacity(k);
    let mut chan_chal_wires: Vec<Vec<LinExpr>> = Vec::with_capacity(k);
    let mut chan_data_wires: Vec<Vec<LinExpr>> = Vec::with_capacity(k);

    for tx in 0..k {
        let obligation = &obligations[tx];
        let native = &natives[tx];
        let proof = native;
        let tx_off_a = tx * per_tx_block_a;
        let tx_off_b = tx * per_tx_block_b;
        // Shape checks (same contract as the inline discharge).
        assert_eq!(proof.commitment.log_rows, num_vars);
        assert_eq!(proof.commitment.n_cols, 1);
        assert_eq!(obligation.reduction.point.len(), num_vars);
        assert_eq!(obligation.commitment_cap_lanes.len(), proof.commitment.cap.hashes.len());

        // Recover the NATIVE reduction point (tower) from the obligation wires.
        let point: Vec<Block128> = obligation
            .reduction
            .point
            .iter()
            .map(|e| {
                let f = e.eval(b.values());
                let flat = (f.lo as u128) | ((f.hi as u128) << 64);
                Block128::from(flat_to_tower_u128(flat))
            })
            .collect();

        let opening = &proof.opening;
        let fri = &opening.fri_proof;
        let src = &opening.source_proof;
        let right_tower = &point[..n_rounds];

        // Source tree (SB1.2): Code(H·eq_right) → φ into the flat basis.
        let eq_r = eq_tensor_tower(right_tower);
        let g: Vec<Block128> = src.h_evals.iter().zip(eq_r.iter()).map(|(&h, &e)| h * e).collect();
        let g_code = Code::new_parallel(&g, &ntt);
        let g_code_flat: Vec<F128> = g_code.encoding.iter().map(|&bb| phi(bb)).collect();
        assert_eq!(tree.code_len(), g_code_flat.len());
        let st_cols = build_source_tree_columns(&tree, &g_code_flat, st_wlog);
        let st_code_cols = build_source_code_columns(&tree, &g_code_flat, st_wlog);
        let fri_root0 = lanes_flat(&fri.fri_roots[0]);
        assert_eq!(st_cols.root, fri_root0, "region tree root != φ(fri_roots[0])");

    // -------------------------------------------------------------------
    // Walk-C channel: the FRICHANL transcript is discharged as a data-parallel
    // duplex chain (see the WALK C section). Here we extract this tx's
    // class-fixed schedule + concrete duplex columns, allocate the
    // squeezed-challenge wires the per-tx algebra consumes, and collect the
    // absorbed-data wires in schedule order. The permutations move onto the
    // shared walk C — no inline channel replay.
    // -------------------------------------------------------------------
    let all_openings = alloc_blocks(b, &opening.all_openings);
    let upper = alloc_blocks(b, &fri.upper_partial_evals);
    let h_evals_w = alloc_blocks(b, &src.h_evals);
    let fri_roots_w: Vec<[LinExpr; 2]> = fri.fri_roots.iter().map(|r| alloc_digest(b, r)).collect();
    let fri_root0_w = fri_roots_w[0].clone();
    let folded_roots_w: Vec<[LinExpr; 2]> =
        src.folded_roots.iter().map(|r| alloc_digest(b, r)).collect();
    let point_w = &obligation.reduction.point;

    // This tx's channel schedule + duplex columns (native); the squeezed
    // challenge wires in schedule order are
    // [gamma, beta×tau, r×n_rounds, source_sq×n_source_q, fri_sq×n_fri_q]
    // (gamma = chal_w[0] is unused, exactly as the inline channel discards it).
    let schedule = capsule_pcs_channel_schedule(proof, num_vars, &point, COMPACT_NUM_QUERIES);
    let dcols = build_duplex_columns(&chan_layout, iv_c, &schedule.data_flat, block_log_c);
    let chal_w: Vec<LinExpr> =
        dcols.challenges.iter().map(|&v| LinExpr::from_wire(b.alloc_f128(v))).collect();
    assert_eq!(chal_w.len(), 1 + tau + n_rounds + n_source_q + n_fri_q, "channel challenge count");
    let beta: Vec<LinExpr> = chal_w[1..1 + tau].to_vec();
    let random_point: Vec<LinExpr> = chal_w[1 + tau..1 + tau + n_rounds].to_vec();
    let source_sq: Vec<LinExpr> = chal_w[1 + tau + n_rounds..1 + tau + n_rounds + n_source_q].to_vec();
    let fri_sq: Vec<LinExpr> = chal_w[1 + tau + n_rounds + n_source_q..].to_vec();

    let batched_claim = all_openings[0].clone();
    let (right_w, left_w) = point_w.split_at(n_rounds);
    // 3c: the derived batched claim == the absorbed claim (== openings[0]).
    let left_eq = eq_ind_partial_eval_trace(b, left_w);
    let mut derived = LinExpr::zero();
    for (l, u) in left_eq.iter().zip(upper.iter()) {
        derived = derived.add(&mul(b, l, u));
    }
    pin_eq(b, &derived, &batched_claim);

    // 3d: tensor-batching claim from beta.
    let batching_eq = eq_ind_partial_eval_trace(b, &beta);
    let mut claim = LinExpr::zero();
    for (u, be) in upper.iter().zip(batching_eq.iter()) {
        claim = claim.add(&mul(b, u, be));
    }
    let initial_claim = claim.clone();
    // SB1.1: H(right) == initial sumcheck claim.
    let h_at_right = mle_evaluate_small_trace(b, &h_evals_w, right_w);
    pin_eq(b, &h_at_right, &initial_claim);

    // 3e sumcheck rounds: c1 == running claim; fold via the walk-C challenge r.
    // The oracle/root absorbs are captured in `data_wires` (bound to the A-lane
    // cells after the loop); r arrives from the carry cells.
    let mut c0_w: Vec<LinExpr> = Vec::with_capacity(n_rounds);
    let mut c1_w: Vec<LinExpr> = Vec::with_capacity(n_rounds);
    for round in 0..n_rounds {
        let c0 = alloc_blocks(b, std::slice::from_ref(&fri.sum_check_oracles[round][0]))[0].clone();
        let c1 = alloc_blocks(b, std::slice::from_ref(&fri.sum_check_oracles[round][1]))[0].clone();
        pin_eq(b, &c1, &claim);
        claim = c0.add(&mul(b, &c1, &random_point[round]));
        c0_w.push(c0);
        c1_w.push(c1);
    }
    // 3f final codeword.
    let final_cw = alloc_blocks(b, &fri.final_codeword);

    // SB3 source query draw + 3h FRI query draw, from the walk-C carry-cell
    // squeezes (positions derived identically to the inline channel).
    let (query_indices, query_bits) =
        compact_queries_from_squeezes_with_bits(b, &source_sq, log_n + LOG_RATE);
    assert!(query_indices.len() >= nq, "need at least nq source queries");
    let (fri_queries, fri_query_bits) =
        compact_queries_from_squeezes_with_bits(b, &fri_sq, n_rounds + LOG_RATE);
    assert!(fri_queries.len() >= nq_fri, "need at least nq_fri FRI queries");
    // Cross-check the walk-C draws against the REAL noid_fri::Channel.
    let (native_source_queries, native_fri_queries) =
        derive_queries(proof, &point, COMPACT_NUM_QUERIES);
    assert_eq!(query_indices, native_source_queries, "walk-C source queries match native");
    assert_eq!(fri_queries, native_fri_queries, "walk-C FRI queries match native");

    // Absorbed-data wires in schedule order (bound to the A-lane cells after the
    // loop). Order MUST mirror `capsule_pcs_channel_schedule`; the eval assert is
    // the safety net against any lane-convention or ordering drift.
    let mut data_wires: Vec<LinExpr> = Vec::with_capacity(schedule.data_flat.len());
    for lane in &obligation.commitment_cap_lanes {
        data_wires.push(lane[0].clone());
        data_wires.push(lane[1].clone());
    }
    for w in &all_openings {
        data_wires.push(w.clone());
    }
    for w in point_w.iter() {
        data_wires.push(w.clone());
    }
    data_wires.push(all_openings[0].clone());
    for round in 0..n_rounds {
        data_wires.push(c0_w[round].clone());
        data_wires.push(c1_w[round].clone());
        data_wires.push(fri_roots_w[round][0].clone());
        data_wires.push(fri_roots_w[round][1].clone());
    }
    for w in &final_cw {
        data_wires.push(w.clone());
    }
    for w in &h_evals_w {
        data_wires.push(w.clone());
    }
    for r in &folded_roots_w {
        data_wires.push(r[0].clone());
        data_wires.push(r[1].clone());
    }
    assert_eq!(data_wires.len(), schedule.data_flat.len(), "absorb data lane count");
    for (kk, w) in data_wires.iter().enumerate() {
        assert_eq!(w.eval(b.values()), schedule.data_flat[kk], "absorb data wire {kk}");
    }

    chan_data_streams.push(schedule.data_flat.clone());
    chan_chal_wires.push(chal_w);
    chan_data_wires.push(data_wires);

    // SB1.2: g_code = Code(H·eq_right) computed in-trace.
    let eq_right_w = eq_ind_partial_eval_trace(b, right_w);
    let mut g_evals_w = Vec::with_capacity(h_evals_w.len());
    for (h, e) in h_evals_w.iter().zip(eq_right_w.iter()) {
        g_evals_w.push(mul(b, h, e));
    }
    let g_code_w = code_new_trace(&g_evals_w);
    assert_eq!(g_code_w.len(), g_code_flat.len());

    // h_code = Code(h_evals) for the SB9 closure.
    let h_code = Code::new_parallel(&src.h_evals, &ntt);
    let h_code_w = code_new_trace(&h_evals_w);
    assert_eq!(h_code_w.len(), h_code.encoding.len());

    // -------------------------------------------------------------------
    // Fill this tx's meta columns (source_tree at the tx block start, leaves
    // after it) into the shared K-wide walk-A columns.
    // -------------------------------------------------------------------
    // Source_tree at [tx_off_a, tx_off_a + st_slots).
    for j in 0..2 {
        cols[CODE0 + j][tx_off_a..tx_off_a + st_slots].copy_from_slice(&st_code_cols[j]);
        cols[KID0 + j][tx_off_a..tx_off_a + st_slots].copy_from_slice(&st_cols.kid[j]);
    }
    for j in 0..STATE_SIZE {
        cols[C0 + j][tx_off_a..tx_off_a + st_slots].copy_from_slice(&st_cols.c[j]);
        s0[j][tx_off_a..tx_off_a + st_slots].copy_from_slice(&st_cols.s0[j]);
        s_out[j][tx_off_a..tx_off_a + st_slots].copy_from_slice(&st_cols.s_out[j]);
    }

    // Source query -> source pair indices; source symbols. The bit-wire twin
    // of `high_pair_leaf_index` tracks the transcript-bound position bits in
    // lockstep, so the fold chain's coset/parity selectors are witness wires
    // (not native constants that would drift the shape).
    let source_pair_indices: Vec<usize> =
        query_indices.iter().map(|&qi| high_pair_leaf_index(qi, log_n)).collect();
    let source_pair_bits: Vec<Vec<LinExpr>> = (0..nq)
        .map(|q| high_pair_leaf_index_bits(&query_bits[q], log_n))
        .collect();

    // SB6 source-leaf family (family 0): nq tiles at this tx's block.
    let sb6_base = tx_off_a + leaf_base(0);
    let mut sb6_syms: Vec<[F128; 2]> = Vec::with_capacity(nq);
    let mut sb6_digest_vals: Vec<[F128; 2]> = Vec::with_capacity(nq);
    for q in 0..nq {
        let leaf_idx = source_pair_indices[q];
        let s0v = src.source_symbols[q * 2];
        let s1v = src.source_symbols[q * 2 + 1];
        let syms = [phi(s0v), phi(s1v)];
        sb6_syms.push(syms);
        let tile = build_source_leaf_columns(&leaf_chain, log_n, leaf_idx, &syms, leaf_stride_log);
        sb6_digest_vals.push(tile.digest);
        let off = sb6_base + q * leaf_stride;
        for j in 0..2 {
            cols[IN0 + j][off..off + leaf_stride].copy_from_slice(&tile.in_[j]);
        }
        for j in 0..STATE_SIZE {
            cols[C0 + j][off..off + leaf_stride].copy_from_slice(&tile.c[j]);
            s0[j][off..off + leaf_stride].copy_from_slice(&tile.s0[j]);
            s_out[j][off..off + leaf_stride].copy_from_slice(&tile.s_out[j]);
        }
    }

    // SB8 high-pair families: fold-chain index/symbol bookkeeping.
    let current: Vec<usize> = source_pair_indices[..nq].to_vec();
    struct LayerData {
        layer_log: usize,
        pair_indices: Vec<usize>,
        syms: Vec<(Block128, Block128)>,
    }
    let mut layers: Vec<LayerData> = Vec::with_capacity(n_layers);
    {
        let mut cur = current.clone();
        for layer in 0..n_layers {
            let layer_log = log_n - 1 - layer;
            let symbols = &src.folded_queried_symbols[layer];
            let pair_indices: Vec<usize> =
                cur.iter().map(|&idx| high_pair_leaf_index(idx, layer_log)).collect();
            let syms: Vec<(Block128, Block128)> = (0..nq).map(|q| symbols[q]).collect();
            layers.push(LayerData { layer_log, pair_indices: pair_indices.clone(), syms });
            cur = pair_indices;
        }
    }

    let mut sb8_digest_vals: Vec<Vec<[F128; 2]>> = Vec::with_capacity(n_layers);
    for (layer, ld) in layers.iter().enumerate() {
        let base = tx_off_a + leaf_base(layer + 1);
        let mut layer_digests: Vec<[F128; 2]> = Vec::with_capacity(nq);
        for q in 0..nq {
            let (s0v, s1v) = ld.syms[q];
            let tile = build_high_pair_leaf_columns(
                ld.layer_log,
                ld.pair_indices[q],
                phi(s0v),
                phi(s1v),
                leaf_stride_log,
            );
            layer_digests.push(tile.digest);
            let off = base + q * leaf_stride;
            for j in 0..2 {
                cols[IN0 + j][off..off + leaf_stride].copy_from_slice(&tile.in_[j]);
            }
            for j in 0..STATE_SIZE {
                cols[C0 + j][off..off + leaf_stride].copy_from_slice(&tile.c[j]);
                s0[j][off..off + leaf_stride].copy_from_slice(&tile.s0[j]);
                s_out[j][off..off + leaf_stride].copy_from_slice(&tile.s_out[j]);
            }
        }
        sb8_digest_vals.push(layer_digests);
    }

    // Append this tx's source-tree exposure slice into the tiled columns (ONE
    // sumcheck after the loop). `kid_lo` = the 2^(st_wlog-1) node digests; the
    // full C carries them at odd slots (`Window(C,1,1)[w] = C[2w+1]`). Concatenated
    // in tx order, the K trees tile at KID period 2L / C period 4L.
    let half = 1usize << (st_wlog - 1);
    expo_kid0.extend_from_slice(&st_cols.kid[0][..half]);
    expo_kid1.extend_from_slice(&st_cols.kid[1][..half]);
    expo_c0.extend_from_slice(&st_cols.c[0]);
    expo_c1.extend_from_slice(&st_cols.c[1]);

    // -------------------------------------------------------------------
    // Grand pins: SB1.2 CODE + root; SB7->SB9 fold chain (walk-A-indexed
    // claims, accumulated per tx). Slots are absolute (tx block offset).
    // -------------------------------------------------------------------
    for i in 0..l {
        let slot = tx_off_a + 2 * (l + i) + 1;
        for lane in 0..2 {
            cell_pins_a.push((CODE0 + lane, slot, g_code_w[2 * i + lane].clone()));
        }
    }
    for lane in 0..2 {
        cell_pins_a.push((C0 + lane, tx_off_a + 3, fri_root0_w[lane].clone()));
    }

    // SB7 + SB8 fold chain, source symbols pinned to SB6 IN columns.
    let mut folded_w: Vec<LinExpr> = Vec::with_capacity(nq);
    for q in 0..nq {
        let s0w = LinExpr::from_wire(b.alloc_f128(sb6_syms[q][0]));
        let s1w = LinExpr::from_wire(b.alloc_f128(sb6_syms[q][1]));
        let off = sb6_base + q * leaf_stride + 4;
        cell_pins_a.push((IN0, off, s0w.clone()));
        cell_pins_a.push((IN0 + 1, off, s1w.clone()));
        let folded = tensor_high_fold_pair_trace(
            b,
            &beta[tau - 1],
            log_n,
            &source_pair_bits[q][log_n - 1..],
            &s0w,
            &s1w,
        );
        folded_w.push(folded);
    }

    let mut cur_idx = current.clone();
    let mut cur_bits = source_pair_bits.clone();
    for (layer, ld) in layers.iter().enumerate() {
        let base = tx_off_a + leaf_base(layer + 1);
        let r = &beta[tau - 2 - layer];
        let mut next_w: Vec<LinExpr> = Vec::with_capacity(nq);
        let mut next_bits: Vec<Vec<LinExpr>> = Vec::with_capacity(nq);
        for q in 0..nq {
            let (s0v, s1v) = ld.syms[q];
            let s0f = phi(s0v);
            let s1f = phi(s1v);
            let s0w = LinExpr::from_wire(b.alloc_f128(s0f));
            let s1w = LinExpr::from_wire(b.alloc_f128(s1f));
            let off = base + q * leaf_stride + 4;
            cell_pins_a.push((IN0, off, s0w.clone()));
            cell_pins_a.push((IN0 + 1, off, s1w.clone()));
            // Continuity: the prior fold equals THIS pair's symbol at the query
            // parity (bit `layer_log−1` of the propagated index). Select via the
            // witness parity bit `s0 + p·(s0+s1)` — a native `if parity` pick of
            // s0/s1 reads a different wire per block and drifts the shape.
            let parity_bit = &cur_bits[q][ld.layer_log - 1];
            let sel = s0w.add(&mul(b, parity_bit, &s0w.add(&s1w)));
            pin_eq(b, &folded_w[q], &sel);
            let pair_bits = high_pair_leaf_index_bits(&cur_bits[q], ld.layer_log);
            let folded = tensor_high_fold_pair_trace(
                b,
                r,
                ld.layer_log,
                &pair_bits[ld.layer_log - 1..],
                &s0w,
                &s1w,
            );
            next_w.push(folded);
            next_bits.push(pair_bits);
        }
        folded_w = next_w;
        cur_idx = ld.pair_indices.clone();
        cur_bits = next_bits;
    }

    // SB9: the closed fold == h_code[cur_idx[q]]. Select the h_code entry with
    // the propagated index BITS (`cur_bits[q]`, transcript-bound) via a mux, not
    // a native `h_code_w[idx]` read whose column would drift with the query
    // position. `cur_idx[q] < h_code_w.len()` so its low `n_idx_bits` bits (the
    // rest are zero) address the code.
    assert!(h_code_w.len().is_power_of_two(), "h_code length power of two");
    let n_idx_bits = h_code_w.len().trailing_zeros() as usize;
    for q in 0..nq {
        assert!(cur_idx[q] < h_code_w.len(), "SB9 index in range");
        assert!(cur_bits[q].len() >= n_idx_bits, "SB9 index bit width");
        let selected = select_by_bits(b, &cur_bits[q][..n_idx_bits], &h_code_w);
        pin_eq(b, &folded_w[q], &selected);
    }
    let _ = &h_code;
    let _ = current.as_slice();

    // ===================================================================
    // WALK A leaf-digest wires -> SB6 / SB8 Merkle entries (shared wires).
    // ===================================================================
    let digest_slot = leaf_chain.digest_slot();
    let mut sb6_digest_wires: Vec<[LinExpr; 2]> = Vec::with_capacity(nq);
    for q in 0..nq {
        let slot = sb6_base + q * leaf_stride + digest_slot;
        let mut wires = [LinExpr::zero(), LinExpr::zero()];
        for lane in 0..2 {
            let v = LinExpr::from_wire(b.alloc_f128(sb6_digest_vals[q][lane]));
            cell_pins_a.push((C0 + lane, slot, v.clone()));
            wires[lane] = v;
        }
        sb6_digest_wires.push(wires);
    }
    // The deepest SB8 fold layers (smallest trees) are authenticated.
    assert!(
        params.sb8_auth_layers <= n_layers,
        "sb8_auth_layers exceeds available fold layers"
    );
    let sb8_auth_layers: Vec<usize> =
        (0..params.sb8_auth_layers).map(|k| n_layers - 1 - k).collect();
    let mut sb8_digest_wires: Vec<Vec<[LinExpr; 2]>> = Vec::new();
    for &layer in &sb8_auth_layers {
        let base = tx_off_a + leaf_base(layer + 1);
        let mut lw = Vec::with_capacity(nq);
        for q in 0..nq {
            let slot = base + q * leaf_stride + digest_slot;
            let mut wires = [LinExpr::zero(), LinExpr::zero()];
            for lane in 0..2 {
                let v = LinExpr::from_wire(b.alloc_f128(sb8_digest_vals[layer][q][lane]));
                cell_pins_a.push((C0 + lane, slot, v.clone()));
                wires[lane] = v;
            }
            lw.push(wires);
        }
        sb8_digest_wires.push(lw);
    }

    // ===================================================================
    // WALK B (per tx): pair-leaf at [tx_off_b, tx_off_b + nq), the three Merkle
    // legs at tx_off_b + meta_base(f); accumulate per-leg-type across txs. Root
    // claim VALUES are the FS-observed root wires (transcript-bound).
    // ===================================================================
    let fri_pair_indices: Vec<usize> =
        fri_queries[..nq_fri].iter().map(|&qi| (qi >> round) >> 1).collect();
    let fri_pairs: Vec<(F128, F128)> = (0..nq_fri)
        .map(|q| {
            let (s0v, s1v) = fri.fri_queried_symbols[round][q];
            (phi(s0v), phi(s1v))
        })
        .collect();
    let pair_wlog = nq_fri.trailing_zeros() as usize;
    let (pair_cols, tx_pair_digests) = build_pair_leaf_columns(&fri_pairs, pair_wlog);
    for j in 0..2 {
        cb[j][tx_off_b..tx_off_b + nq_fri].copy_from_slice(&pair_cols.in_[j][0..nq_fri]);
    }
    for j in 0..STATE_SIZE {
        cb[2 + j][tx_off_b..tx_off_b + nq_fri].copy_from_slice(&pair_cols.c[j][0..nq_fri]);
        s0b[j][tx_off_b..tx_off_b + nq_fri].copy_from_slice(&pair_cols.s0[j][0..nq_fri]);
        soutb[j][tx_off_b..tx_off_b + nq_fri].copy_from_slice(&pair_cols.s_out[j][0..nq_fri]);
    }
    for q in 0..nq_fri {
        pair_digests.push(tx_pair_digests[q]);
        pair_slots.push(tx_off_b + q);
    }

    // Leg 0: 3i FRI-round openings (single per-round root == fri_roots_w[round]).
    {
        let f = 0usize;
        let depth = leg_depths[f];
        let meta_base = meta_bases[f];
        let col_base = 6;
        let stride = (2 * depth).next_power_of_two();
        let n_slots = nq_fri * stride;
        let fam_wlog = n_slots.trailing_zeros() as usize;
        let all_pi: Vec<usize> = fri_queries.iter().map(|&qi| (qi >> round) >> 1).collect();
        let all_leaves: Vec<[u8; 32]> = fri.fri_queried_symbols[round]
            .iter()
            .map(|(s0v, s1v)| hasher.hash_pair(s0v, s1v))
            .collect();
        let batch = BatchedMerkleProof { siblings: fri.fri_merkle_batch[round].siblings.clone() };
        let paths = expand_batched_merkle_proof(&batch, depth, &all_pi, &all_leaves, &hasher)
            .expect("3i FRI octopus expand");
        all_expands_ok &= !paths.is_empty();
        let root_flat = lanes_flat(&fri.fri_roots[round]);
        let mut witnesses = Vec::with_capacity(nq_fri);
        for q in 0..nq_fri {
            let path = paths
                .iter()
                .find(|p| p.leaf_index == fri_pair_indices[q])
                .expect("3i FRI path");
            let leaf_flat = lanes_flat(&path.leaf_hash);
            assert_eq!(tx_pair_digests[q], leaf_flat, "3i pair-leaf digest != φ(native leaf)");
            witnesses.push(MerklePathWitness {
                entry: leaf_flat,
                siblings: path.siblings.iter().map(lanes_flat).collect(),
                directions: path.directions.clone(),
            });
            acc_committed_roots[f].push(root_flat);
            acc_root_wires[f].push(fri_roots_w[round].clone());
            acc_path_slots[f].push(tx_off_b + meta_base + q * stride);
            acc_pair_map.push(tx * nq_fri + q);
        }
        let family = MerklePathFamily { depth, n_paths: nq_fri };
        let mcols = build_merkle_path_columns(&family, iv_b, &witnesses, fam_wlog);
        place_merkle(&mut cb, &mut s0b, &mut soutb, &mcols, col_base, tx_off_b + meta_base, n_slots);
        acc_recomputed_roots[f].extend(mcols.roots.iter().copied());
    }

    // Leg 1: SB6 source-tree opening (authenticated to the committed CAP; the
    // root == the FS-observed source-cap lane of the ABSORBED commitment cap).
    {
        let f = 1usize;
        let depth = leg_depths[f];
        let meta_base = meta_bases[f];
        let col_base = 6;
        let stride = (2 * depth).next_power_of_two();
        let n_slots = nq * stride;
        let fam_wlog = n_slots.trailing_zeros() as usize;
        let cap_flat: Vec<[F128; 2]> = source_cap_from_commitment_cap(&proof.commitment.cap, log_n)
            .expect("source cap")
            .iter()
            .map(lanes_flat)
            .collect();
        let all_leaves: Vec<[u8; 32]> = source_pair_indices
            .iter()
            .enumerate()
            .map(|(q, &li)| {
                let syms = [src.source_symbols[q * 2], src.source_symbols[q * 2 + 1]];
                source_leaf_hash(CommitmentHashBackend::Arithmetic, log_n, 1, li, &syms, &hasher)
            })
            .collect();
        let batch = BatchedMerkleProof { siblings: src.source_merkle_batch.siblings.clone() };
        let paths = expand_batched_merkle_proof_to_cap(
            &batch,
            source_tree_depth(log_n),
            source_cap_depth(log_n),
            &source_pair_indices,
            &all_leaves,
            &hasher,
        )
        .expect("SB6 source octopus expand");
        all_expands_ok &= !paths.is_empty();
        let cap_start = 1usize << MERKLE_CAP_DEPTH;
        // Source-cap lanes selected by `cap_idx = li >> sb6_walk_depth` — a
        // block-dependent query position. A native `commitment_cap_lanes[cap_start
        // + cap_idx]` makes the SB6 root wire (and the claim opened to it)
        // reference a position-dependent WIRE, which drifts the LINK matrix (the
        // claim's value LinExpr is pinned to the IO tail only in the link, so it
        // escapes the block-slot matrix check). Select via a witness-bit mux over
        // the `2^cap_depth` source-cap lanes instead; `cap_idx`'s bits are the
        // high bits of the transcript-bound `source_pair_bits[q]`.
        let cap_depth = source_cap_depth(log_n);
        let n_cap = 1usize << cap_depth;
        let cap_lane0: Vec<LinExpr> = (0..n_cap)
            .map(|i| obligation.commitment_cap_lanes[cap_start + i][0].clone())
            .collect();
        let cap_lane1: Vec<LinExpr> = (0..n_cap)
            .map(|i| obligation.commitment_cap_lanes[cap_start + i][1].clone())
            .collect();
        let mut witnesses = Vec::with_capacity(nq);
        for q in 0..nq {
            let li = source_pair_indices[q];
            let path = paths.iter().find(|p| p.leaf_index == li).expect("SB6 source path");
            assert_eq!(path.siblings.len(), sb6_walk_depth, "SB6 path is walk-depth long");
            let leaf_flat = lanes_flat(&path.leaf_hash);
            assert_eq!(sb6_digest_vals[q], leaf_flat, "SB6 leaf digest != φ(native leaf)");
            witnesses.push(MerklePathWitness {
                entry: leaf_flat,
                siblings: path.siblings.iter().map(lanes_flat).collect(),
                directions: path.directions.clone(),
            });
            let cap_idx = li >> sb6_walk_depth;
            acc_committed_roots[f].push(cap_flat[cap_idx]);
            // TRANSCRIPT-BINDING: root == the FS-observed source-cap lane, muxed
            // by the query-position bits (value-identical to the native index).
            assert!(
                source_pair_bits[q].len() >= sb6_walk_depth + cap_depth,
                "SB6 cap index bit width"
            );
            let cap_bits = &source_pair_bits[q][sb6_walk_depth..sb6_walk_depth + cap_depth];
            acc_root_wires[f].push([
                select_by_bits(b, cap_bits, &cap_lane0),
                select_by_bits(b, cap_bits, &cap_lane1),
            ]);
            acc_entry_wires[f].push(sb6_digest_wires[q].clone());
            acc_path_slots[f].push(tx_off_b + meta_base + q * stride);
        }
        let family = MerklePathFamily { depth, n_paths: nq };
        let mcols = build_merkle_path_columns(&family, iv_b, &witnesses, fam_wlog);
        place_merkle(&mut cb, &mut s0b, &mut soutb, &mcols, col_base, tx_off_b + meta_base, n_slots);
        acc_recomputed_roots[f].extend(mcols.roots.iter().copied());
    }

    // Legs 2..: SB8 high-fold layer openings (root == the FS-observed
    // folded_roots_w[layer] wire, absorbed before the source query draw).
    for (kk, &layer) in sb8_auth_layers.iter().enumerate() {
        let f = 2 + kk;
        let depth = leg_depths[f];
        let meta_base = meta_bases[f];
        let col_base = 6;
        let stride = (2 * depth).next_power_of_two();
        let n_slots = nq * stride;
        let fam_wlog = n_slots.trailing_zeros() as usize;
        let layer_log = log_n - 1 - layer;
        let li_all: Vec<usize> = {
            let mut cur = source_pair_indices.clone();
            for ll in 0..layer {
                let lll = log_n - 1 - ll;
                cur = cur.iter().map(|&idx| high_pair_leaf_index(idx, lll)).collect();
            }
            cur.iter().map(|&idx| high_pair_leaf_index(idx, layer_log)).collect()
        };
        let layer_symbols = &src.folded_queried_symbols[layer];
        let all_leaves: Vec<[u8; 32]> = li_all
            .iter()
            .enumerate()
            .map(|(q, &li)| {
                let (s0v, s1v) = layer_symbols[q];
                high_pair_leaf_hash_for_trace(layer_log, li, s0v, s1v, &hasher)
            })
            .collect();
        let batch = BatchedMerkleProof { siblings: src.folded_merkle_batch[layer].siblings.clone() };
        let paths = expand_batched_merkle_proof(&batch, depth, &li_all, &all_leaves, &hasher)
            .expect("SB8 high-fold octopus expand");
        all_expands_ok &= !paths.is_empty();
        let root_flat = lanes_flat(&src.folded_roots[layer]);
        let chosen: Vec<usize> = layers[layer].pair_indices[..nq].to_vec();
        let mut witnesses = Vec::with_capacity(nq);
        for q in 0..nq {
            let li = chosen[q];
            let path = paths.iter().find(|p| p.leaf_index == li).expect("SB8 path");
            let leaf_flat = lanes_flat(&path.leaf_hash);
            assert_eq!(sb8_digest_vals[layer][q], leaf_flat, "SB8 leaf digest != φ(native leaf)");
            witnesses.push(MerklePathWitness {
                entry: leaf_flat,
                siblings: path.siblings.iter().map(lanes_flat).collect(),
                directions: path.directions.clone(),
            });
            acc_committed_roots[f].push(root_flat);
            // TRANSCRIPT-BINDING: root == the FS-observed folded-layer root wire.
            acc_root_wires[f].push(folded_roots_w[layer].clone());
            acc_entry_wires[f].push(sb8_digest_wires[kk][q].clone());
            acc_path_slots[f].push(tx_off_b + meta_base + q * stride);
        }
        let family = MerklePathFamily { depth, n_paths: nq };
        let mcols = build_merkle_path_columns(&family, iv_b, &witnesses, fam_wlog);
        place_merkle(&mut cb, &mut s0b, &mut soutb, &mcols, col_base, tx_off_b + meta_base, n_slots);
        acc_recomputed_roots[f].extend(mcols.roots.iter().copied());
    }

    // FRI fold-join (walk-B-indexed claims, per tx): the queried symbols == the
    // pair-leaf IN columns, folded to the final codeword (round 0: no
    // previous-round fold consistency).
    let final_len = fri.final_codeword.len();
    assert!(final_len.is_power_of_two(), "final codeword length power of two");
    let final_bits = final_len.trailing_zeros() as usize;
    for q in 0..nq_fri {
        let (s0v, s1v) = fri.fri_queried_symbols[round][q];
        let s0w = LinExpr::from_wire(b.alloc_f128(phi(s0v)));
        let s1w = LinExpr::from_wire(b.alloc_f128(phi(s1v)));
        cell_pins_b.push((pair_refs.in_[0], tx_off_b + q, s0w.clone()));
        cell_pins_b.push((pair_refs.in_[1], tx_off_b + q, s1w.clone()));
        let folded = fold_trace_bits(
            b,
            &random_point[round],
            round,
            &fri_query_bits[q][round + 1..],
            &s0w,
            &s1w,
            &ntt,
        );
        // final_idx = (fri_queries[q] >> n_rounds) % final_len — the low
        // `final_bits` bits of (fri_queries[q] >> n_rounds), i.e. position bits
        // [n_rounds .. n_rounds+final_bits]. Select via those witness bits (was
        // a native `final_cw[final_idx]` read whose column drifts).
        assert!(
            fri_query_bits[q].len() >= n_rounds + final_bits,
            "fold-join index bit width"
        );
        let sel = select_by_bits(
            b,
            &fri_query_bits[q][n_rounds..n_rounds + final_bits],
            &final_cw,
        );
        pin_eq(b, &folded, &sel);
    }

        // Close this tx's discharge contract: the batched primary opening ==
        // the value the owner-auth killshot reduced to.
        pin_eq(b, &all_openings[0], &obligation.reduction.value);
    } // end `for tx in 0..k`

    // ===================================================================
    // Exact-state families (block-level, chunked across the K tx blocks —
    // NEVER a new walk): the 2T slot-leaf sponge tiles fill walk A's es
    // region; the state/guard Merkle paths fill walk B's es legs. Chunk i
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
                .map(|l| (l.amount_flat, l.owner_hi_flat, l.owner_lo_flat))
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
                cell_pins_a.push((IN0, off, leaf.amount_w.clone()));
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
                    assert_eq!(path.entry_leaf_index, g, "leaf↔path pairing is index-aligned");
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
                6,
                blk * per_tx_block_b + meta_bases[es_state_leg],
                &state_paths,
            );

            // --- Walk B: this block's guard-path chunk (present iff guard;
            // entries = the INLINE guard-bucket statement's leaf digests,
            // roots = the composite statement's guard roots). ---
            if let Some(gd) = &e.guard {
                let cap = leg_caps[es_guard_leg];
                let glo = (blk * cap).min(2);
                let ghi = ((blk + 1) * cap).min(2);
                let guard_paths: Vec<EsPathReal> = (glo..ghi)
                    .map(|i| {
                        assert_eq!(gd.siblings[i].len(), gd.depth, "guard path depth");
                        EsPathReal {
                            entry_flat: gd.entries_flat[i],
                            entry_w: gd.entries_w[i].clone(),
                            siblings: gd.siblings[i].clone(),
                            directions: gd.directions[i].clone(),
                            root_flat: gd.roots_flat[i],
                            root_w: gd.roots_w[i].clone(),
                        }
                    })
                    .collect();
                fill_es_merkle_leg(
                    &mut cb,
                    &mut s0b,
                    &mut soutb,
                    &mut acc_entry_wires[es_guard_leg],
                    &mut acc_root_wires[es_guard_leg],
                    &mut acc_committed_roots[es_guard_leg],
                    &mut acc_path_slots[es_guard_leg],
                    &mut acc_recomputed_roots[es_guard_leg],
                    gd.depth,
                    cap,
                    leg_ivs[es_guard_leg],
                    6,
                    blk * per_tx_block_b + meta_bases[es_guard_leg],
                    &guard_paths,
                );
            }
        }
    }

    // ===================================================================
    // Tx-root paths (block-level, chunked like the exact-state families):
    // one TAG_COMPRESS walk-B leg, entries = the spine tx-hash wires, every
    // root = the header tx_root wires. The leaf POSITION is bound by
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
        let d_col = 10;
        let sib_cols = [8, 9];
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
                6,
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
                    s0[j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_s0[j]);
                    s_out[j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_s_out[j]);
                    cols[C0 + j][tile_abs..tile_abs + SPINE_TILE_SLOTS]
                        .copy_from_slice(&icols.tile_c[j]);
                    s0[j][tile_abs..tile_abs + SPINE_TILE_SLOTS]
                        .copy_from_slice(&icols.tile_s0[j]);
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
                        let w =
                            LinExpr::from_wire(b.alloc_f128(icols.chain_digests[t][lane]));
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
    // Walk A (once): source_tree + leaf families over ALL K txs, common-period
    // patterns, K per-tree exposures. The walk/substitution flatten; the K
    // exposures are the only per-tx source-tree residual.
    // ===================================================================
    let iv = compress_iv_flat();
    let mut fixed: Vec<FixedPattern> = Vec::new();
    for pat in source_tree_fixed_patterns(&tree, iv) {
        fixed.push(common_period_pattern(&pat.table, 0, 1, block_log_a));
    }
    for f in 0..n_leaf_families {
        for pat in source_leaf_fixed_patterns(&leaf_chain, iv) {
            fixed.push(common_period_pattern(&pat.table, leaf_base(f), nq, block_log_a));
        }
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
            fixed.push(common_period_pattern(&pat.table, es_leaf_base, es_leaf_cap, block_log_a));
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
            fixed.push(common_period_pattern(&pat.table, spine_tree_base, spine_cap, block_log_a));
        }
        for pat in spine_tile_fixed_patterns() {
            fixed.push(common_period_pattern(&pat.table, spine_tile_base, spine_cap, block_log_a));
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
    let st_refs = SourceTreeRefs {
        code: [CODE0, CODE0 + 1],
        kid: [KID0, KID0 + 1],
        c: std::array::from_fn(|i| C0 + i),
        even_int: 0,
        odd_int: 1,
        leafodd: 2,
        iv: [3, 4],
    };
    let leaf_refs: Vec<SourceLeafRefs> = (0..n_leaf_families)
        .map(|f| SourceLeafRefs {
            in_: [IN0, IN0 + 1],
            c: std::array::from_fn(|i| C0 + i),
            hp: 5 + f * 5,
            even: 5 + f * 5 + 1,
            odd: 5 + f * 5 + 2,
            iv: [5 + f * 5 + 3, 5 + f * 5 + 4],
        })
        .collect();
    let committed: Vec<&[F128]> = cols.iter().map(|c| c.as_slice()).collect();
    let expo_tiled = ExpoTiledSpec {
        kid_meta: [KID0, KID0 + 1],
        c_meta: [C0, C0 + 1],
        tx_log: k.trailing_zeros() as usize,
    };
    let expo_cols: [&[F128]; 4] =
        [expo_kid0.as_slice(), expo_kid1.as_slice(), expo_c0.as_slice(), expo_c1.as_slice()];
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
        &committed, &s0, &s_out, &fixed, &st_refs, &leaf_refs, es_sponge.as_ref(),
        spine_union_spec.as_ref(),
        spine_union_spec.as_ref().map(|_| &spine_expo_cols),
        w_log, &expo_tiled, &expo_cols, st_wlog, block_log_a,
    );
    let mut slices: Vec<WitnessSlice> =
        cols.iter().map(|c| alloc_column_slice(b, c, w_log).0).collect();
    claims.extend(discharge_union(
        b, &fixed, &st_refs, &leaf_refs, es_sponge.as_ref(), spine_union_spec.as_ref(), w_log,
        st_wlog, block_log_a, &expo_tiled, &native_u,
    ));

    // ===================================================================
    // Walk B (once): pair-leaf + the three Merkle legs over ALL K txs,
    // common-period patterns. ONE MerkleLeg per leg-type from the accumulated
    // K*nq paths.
    // ===================================================================
    let mut legs: Vec<MerkleLeg> = Vec::with_capacity(n_legs);
    for f in 0..n_legs {
        let depth = leg_depths[f];
        let fixed_base = 1 + 9 * f;
        legs.push(MerkleLeg {
            family: MerklePathFamily { depth, n_paths: leg_caps[f] },
            refs: union_merkle_refs(fixed_base),
            region: fixed_base + 8,
            committed_roots: std::mem::take(&mut acc_committed_roots[f]),
            entry_wires: std::mem::take(&mut acc_entry_wires[f]),
            pair_entry_map: if f == 0 { Some(std::mem::take(&mut acc_pair_map)) } else { None },
            root_wires: std::mem::take(&mut acc_root_wires[f]),
            path_slots: std::mem::take(&mut acc_path_slots[f]),
            recomputed_roots: std::mem::take(&mut acc_recomputed_roots[f]),
        });
    }
    // Common-period patterns: pair-leaf region at [0, nq), then each leg's 8
    // merkle patterns + a region selector at meta_bases[f], all periodic over the
    // tx block. The IV patterns are per-leg (the exact-state legs run on their
    // own consensus tree tags).
    let mut fixed_b: Vec<FixedPattern> = Vec::new();
    fixed_b.push(common_period_ones(0, nq_fri, block_log_b));
    for f in 0..n_legs {
        let family = MerklePathFamily { depth: leg_depths[f], n_paths: leg_caps[f] };
        for pat in merkle_fixed_patterns(&family, leg_ivs[f]) {
            fixed_b.push(common_period_pattern(&pat.table, meta_bases[f], leg_caps[f], block_log_b));
        }
        fixed_b.push(common_period_ones(meta_bases[f], family.n_slots(), block_log_b));
    }
    let committed_b: Vec<&[F128]> = cb.iter().map(|c| c.as_slice()).collect();
    let native_b = run_merkle_union_native(
        &committed_b, &s0b, &soutb, &fixed_b, &pair_refs, region_pair, &legs, w_log_b, DOMAIN_B,
    );
    let n_slices_a = slices.len();
    let slices_b: Vec<WitnessSlice> =
        cb.iter().map(|c| alloc_column_slice(b, c, w_log_b).0).collect();
    let (mut wb_claims, wb_cell_pins, _pair_digest_wires) = discharge_merkle_union(
        b, &fixed_b, &pair_refs, region_pair, &legs, w_log_b, &native_b, &pair_digests, &pair_slots,
        DOMAIN_B,
    );
    for c in wb_claims.iter_mut() {
        c.slice += n_slices_a;
    }
    slices.extend(slices_b);
    claims.extend(wb_claims);
    // The merkle discharge's per-cell pins (pair-leaf digests, leg entries/roots)
    // join the walk-B cell pins (both index the walk-B slices).
    cell_pins_b.extend(wb_cell_pins);
    assert!(all_expands_ok, "all real-sibling octopus expands returned non-empty paths");

    // Stage 2: resolve the per-cell reads/pins to R1CS constraints (pin_eq), NOT
    // link-IO opening claims. Each column is opened by its walk discharge (random
    // point), so every cell is bound (Schwartz-Zippel); pinning the algebra wire
    // to the cell binds it too, keeping the O(K) per-cell bindings out of the IO.
    // Walk-A cols index `slices` directly; walk-B (fold-join) cols are offset by
    // `n_slices_a`.
    for (col, slot, wire) in &cell_pins_a {
        pin_eq(b, wire, &slot_cell(&slices[*col], *slot));
    }
    for (col, slot, wire) in &cell_pins_b {
        pin_eq(b, wire, &slot_cell(&slices[n_slices_a + *col], *slot));
    }

    // ===================================================================
    // Walk C (once): the K txs' FRICHANL transcript channels, tiled into ONE
    // duplex walk. The squeezed challenges the per-tx algebra consumed are bound
    // to the carry cells; the absorbed proof data is bound to the A-lane cells.
    // The permutations are discharged by ONE walk — transaction-count flat.
    // ===================================================================
    let u_c = build_duplex_union(&chan_layout, iv_c, &chan_data_streams);
    let native_c = run_duplex_union_native(&u_c, DOMAIN_C);
    let n_slices_ab = slices.len();
    let slices_c: Vec<WitnessSlice> =
        u_c.committed.iter().map(|c| alloc_column_slice(b, c, u_c.w_log).0).collect();
    let mut wc_claims = discharge_duplex_union(b, &u_c, DOMAIN_C, &native_c, 0);
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
    slices.extend(slices_c);
    claims.extend(wc_claims);

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

/// `[1, base, base², …, base^{m−1}]` — the trace twin of `squeeze_alphas_trace`
/// with `base` supplied (a carry cell) instead of squeezed. `alphas[0]` is the
/// build-time constant `1`, `alphas[1] = base`, higher powers via `mul` (so the
/// `a.is_const() && a.constant == ONE` fast path in `owner_boundary_w` /
/// `verify_batch_eval_trace` fires on `alphas[0]` exactly as inline).
fn owner_alpha_powers(b: &mut FieldR1csBuilder, base: &LinExpr, m: usize) -> Vec<LinExpr> {
    if m == 0 {
        return Vec::new();
    }
    let mut alphas = Vec::with_capacity(m);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..m {
        alphas.push(acc.clone());
        if alphas.len() < m {
            acc = if alphas.len() == 1 { base.clone() } else { mul(b, &acc, base) };
        }
    }
    alphas
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
/// Challenge order in the walk-C carry cells (`5·num_vars + 3` total, class-
/// fixed by `owner_auth_channel_schedule`):
///   `[rho×nv, r_prime×nv, delta, r_double_prime×nv, boundary_alpha,
///     boundary_point×nv, batch_alpha, r_B×nv]`.
/// The fold outputs `r_prime` / `r_double_prime` / `boundary_point` / `r_B` are
/// the REVERSE of their per-round challenge order (matching the inline twin).
pub fn discharge_owner_auth_killshots_via_region(
    b: &mut FieldR1csBuilder,
    trace_proofs: &[OwnerAuthProofTrace],
    trace_inputs: &[OwnerAuthPublicInputsTrace],
    native_proofs: &[OwnerAuthProofKillShot],
    native_inputs: &[OwnerAuthPublicInputs],
) -> (Vec<PendingAuthPcsObligation>, Vec<RegionPcsClaim>) {
    let k = trace_proofs.len();
    assert!(k >= 1, "at least one owner-auth killshot");
    assert_eq!(trace_inputs.len(), k, "one trace input per killshot");
    assert_eq!(native_proofs.len(), k, "one native proof per killshot");
    assert_eq!(native_inputs.len(), k, "one native input per killshot");

    // Class-fixed channel layout — tx 0 defines it; every tx shares the class.
    let layout0 = native_inputs[0].layout;
    let num_vars = layout0.num_vars;
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
        let nv = layout.num_vars;
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
        let chal_w: Vec<LinExpr> =
            dcols.challenges.iter().map(|&v| LinExpr::from_wire(b.alloc_f128(v))).collect();
        assert_eq!(chal_w.len(), 5 * nv + 3, "owner-auth channel challenge count");

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
            expected =
                proof_t.shift_round_polys[round].evaluate(b, &expected.clone(), &challenge);
            r_double_prime.push(challenge);
        }
        r_double_prime.reverse();
        let w_at_r =
            owner_shift_weights_at_point(b, layout, &main_red.r_prime, &delta, &r_double_prime);
        let rhs = mul(b, &w_at_r, &proof_t.shift_state_at_r2);
        pin_zero(b, &expected.add(&rhs));

        // ----- Boundary sumcheck: alpha + per-round folds from chal_w.
        let constraints = owner_boundary_constraints(b, inputs_t, layout);
        let boundary_alpha = chal_w[3 * nv + 1].clone();
        let alphas = owner_alpha_powers(b, &boundary_alpha, constraints.len());
        let target = owner_boundary_target(b, &constraints, &alphas);
        let mut expected = target;
        let mut boundary_point: Vec<LinExpr> = Vec::with_capacity(nv);
        for round in 0..nv {
            let challenge = chal_w[3 * nv + 2 + round].clone();
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
        let batch_alpha = chal_w[4 * nv + 2].clone();
        let batch_alphas = owner_alpha_powers(b, &batch_alpha, 3);
        let mut claim = claim_values[0].clone();
        for i in 1..3 {
            claim = claim.add(&mul(b, &batch_alphas[i], &claim_values[i]));
        }
        let mut r_b: Vec<LinExpr> = Vec::with_capacity(nv);
        for round in 0..nv {
            let challenge = chal_w[4 * nv + 3 + round].clone();
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
        data_wires.push(inputs_t.owner_count.clone());
        // `live_slots == owner_count` (OWNER_AUTH_SLOTS_PER_OWNER == 1).
        data_wires.push(inputs_t.owner_count.clone());
        data_wires.push(inputs_t.tx_body_hash[0].clone());
        data_wires.push(inputs_t.tx_body_hash[1].clone());
        for vector in [
            &inputs_t.live_input_positions,
            &inputs_t.live_slot_indices,
            &inputs_t.input_to_group,
        ] {
            // `push_padded_input_vector`: live_len, then the padded value/sentinel
            // lanes (the trace vector is already padded to `padded_input_len`).
            data_wires.push(inputs_t.live_len.clone());
            for entry in vector.iter() {
                data_wires.push(entry.clone());
            }
        }
        for pair in &inputs_t.expected_address {
            data_wires.push(pair[0].clone());
            data_wires.push(pair[1].clone());
        }
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
    let slices: Vec<WitnessSlice> =
        u_c.committed.iter().map(|c| alloc_column_slice(b, c, u_c.w_log).0).collect();
    let claims = discharge_duplex_union(b, &u_c, OWNER_AUTH_DOMAIN_C, &native_c, 0);
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

    (obligations, region_claims)
}

// ===========================================================================
// [G] step 4 Stage 1 — the SHARED leaf-union walk (all K txs' leaf tiles, ONE
// family). Every SB6 source-leaf and SB8 high-pair tile of EVERY transaction is
// ONE structure (high-pair discharges with `source_leaf_substitution_terms` —
// the topologically identical n_cols=1 chain), so a single periodic-pattern
// family covers them all in ONE carry-selection + ONE walk + ONE substitution.
// The walk is logarithmic in the tiled domain ⇒ transaction-count independent
// (`[tx_hi | schedule_lo]`). Columns (all length P): IN0=0, IN1=1, C0=2..C3=5.
// ===========================================================================

/// A leaf tile to place in the shared leaf-union domain. These
/// (`build_leaf_union` / `run_leaf_union_native` / `discharge_leaf_union`) are
/// the standalone leaf-ONLY union path — the plural discharge unions leaves WITH
/// the source tree via `run_union_native`, so they are exercised only by the
/// leaf-union unit gates (`leaf_union_slot_end_to_end` proves the discharge→PCS
/// path in isolation); `#[allow(dead_code)]` marks them test-only in a release
/// build.
#[allow(dead_code)]
pub(crate) enum LeafTile {
    /// SB6 source leaf: the `hash`/`compress` chain over two column-hash symbols.
    Source { log_rows: usize, leaf_index: usize, syms: [F128; 2] },
    /// SB8 high-pair leaf: the queried fold pair `(s0, s1)`.
    HighPair { layer_log: usize, leaf_index: usize, s0: F128, s1: F128 },
}

#[allow(dead_code)]
pub(crate) struct LeafUnion {
    pub cols: SourceLeafColumns,
    pub digests: Vec<[F128; 2]>,
    pub w_log: usize,
}

/// Tile every leaf into ONE column set, stride-aligned. The tile count is
/// padded to a power of two with CANONICAL GHOST leaf tiles (a zero-input
/// source-leaf chain) — NOT `perm([0;4])` ghost SLOTS: the periodic patterns
/// (period = stride) fire at every slot, so every slot must be a valid chain
/// tile, else the substitution rejects. Real-tile digests are returned; the
/// ghost tiles pad the domain to a power of two only.
#[allow(dead_code)]
pub(crate) fn build_leaf_union(tiles: &[LeafTile]) -> LeafUnion {
    let chain = SourceLeafChain { n_cols: 1 };
    let stride = chain.stride();
    let stride_log = stride.trailing_zeros() as usize;
    let n_pad = tiles.len().max(1).next_power_of_two();
    let w_log = (n_pad * stride).trailing_zeros() as usize;
    let p = 1usize << w_log;
    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut in_: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut digests = Vec::with_capacity(tiles.len());
    for t in 0..n_pad {
        let tc = match tiles.get(t) {
            Some(LeafTile::Source { log_rows, leaf_index, syms }) => {
                build_source_leaf_columns(&chain, *log_rows, *leaf_index, syms, stride_log)
            }
            Some(LeafTile::HighPair { layer_log, leaf_index, s0: a, s1: bb }) => {
                build_high_pair_leaf_columns(*layer_log, *leaf_index, *a, *bb, stride_log)
            }
            // Ghost padding tile: a valid zero-input source-leaf chain.
            None => build_source_leaf_columns(&chain, 0, 0, &[F128::ZERO, F128::ZERO], stride_log),
        };
        let off = t * stride;
        for j in 0..STATE_SIZE {
            c[j][off..off + stride].copy_from_slice(&tc.c[j]);
            s0[j][off..off + stride].copy_from_slice(&tc.s0[j]);
            s_out[j][off..off + stride].copy_from_slice(&tc.s_out[j]);
        }
        for j in 0..2 {
            in_[j][off..off + stride].copy_from_slice(&tc.in_[j]);
        }
        if t < tiles.len() {
            digests.push(tc.digest);
        }
    }
    let digest = digests.first().copied().unwrap_or([F128::ZERO; 2]);
    LeafUnion { cols: SourceLeafColumns { c, s0, s_out, in_, digest }, digests, w_log }
}

#[allow(dead_code)]
pub(crate) struct LeafUnionNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<(usize, Vec<F128>, F128)>,
}

#[allow(dead_code)]
pub(crate) fn run_leaf_union_native(u: &LeafUnion, domain: &[u8]) -> LeafUnionNative {
    let chain = SourceLeafChain { n_cols: 1 };
    let fixed = source_leaf_fixed_patterns(&chain, compress_iv_flat());
    let refs = source_leaf_refs(0, 0);
    let cols = &u.cols;
    let committed: Vec<&[F128]> =
        vec![&cols.in_[0], &cols.in_[1], &cols.c[0], &cols.c[1], &cols.c[2], &cols.c[3]];
    let internal: Vec<&[F128]> = cols.s_out.iter().map(|c| c.as_slice()).collect();
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
        &RelationColumns { committed: &committed, internal: &internal, fixed: &fixed },
        &mut ch_p,
    );
    let sel_point =
        verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &fixed, &sel_proof, &mut ch_v)
            .expect("native leaf selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms).iter().zip(sel_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }
    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(&cols.s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native leaf walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = source_leaf_substitution_terms(&refs, alpha);
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
        &RelationColumns { committed: &committed, internal: &[], fixed: &fixed },
        &mut ch_p,
    );
    let sub_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &sub_terms,
        &fixed,
        &sub_proof,
        &mut ch_v,
    )
    .expect("native leaf substitution");
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
                pending.push((*c, pt, pr.final_value));
                shifts.push((0usize, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) = prove_shift_discharge_pow2(committed[*c], &sub_point, *v, 1, &mut ch_p);
                let pt = verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v)
                    .expect("shift2");
                pending.push((*c, pt, pr.final_value));
                shifts.push((1usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native leaf-union lockstep");
    LeafUnionNative { sel_proof, walk_proof, sub_proof, shifts, pending }
}

fn leaf_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    refs: &SourceLeafRefs,
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let mds = flat_mds(true);
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        ap.push(acc.clone());
    }
    let m: Vec<LinExpr> = (0..STATE_SIZE)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&ap[e].scale(mds[e][j]));
            }
            a
        })
        .collect();
    let mut terms = Vec::new();
    for i in 0..2 {
        let in_col = ColRef::Committed(refs.in_[i]);
        let c_sh = ColRef::CommittedShift(refs.c[i]);
        let c_sh2 = ColRef::CommittedShift2(refs.c[i]);
        for factors in [
            vec![ColRef::Fixed(refs.hp), in_col],
            vec![ColRef::Fixed(refs.even), c_sh2],
            vec![ColRef::Fixed(refs.odd), c_sh],
            vec![ColRef::Fixed(refs.odd), c_sh2],
        ] {
            terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.iv[j - 2])],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.odd), ColRef::CommittedShift(refs.c[j])],
        });
    }
    (terms, ap)
}

/// Discharge the shared leaf-union in-trace; returns the pending claims plus one
/// `digest_wires` pair per tile (C0/C1 at the tile's digest slot) for wiring
/// into the Merkle entries. Column claims are offset by `base` (the tx-slice
/// base in the caller's global slice table).
#[allow(dead_code)]
pub(crate) fn discharge_leaf_union(
    b: &mut FieldR1csBuilder,
    w_log: usize,
    domain: &[u8],
    native: &LeafUnionNative,
    base: usize,
    tile_digests: &[[F128; 2]],
) -> (Vec<Claim>, Vec<[LinExpr; 2]>) {
    let chain = SourceLeafChain { n_cols: 1 };
    let fixed = source_leaf_fixed_patterns(&chain, compress_iv_flat());
    let refs = source_leaf_refs(0, 0);
    let mut ch = FsChannelTrace::new(b, domain);
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut np_cursor = 0usize;
    let zero = LinExpr::zero();

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_e_terms = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_e_terms
            .push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Committed(refs.c[j])] });
        sel_e_terms
            .push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Internal(j)] });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_e_terms, &fixed, &sel_e);
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
    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let sub_native = source_leaf_substitution_terms(&refs, F128::ONE);
    let (sub_e_terms, ap) = leaf_sub_terms_trace(b, &refs, &alpha);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e =
        ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&sub_native).len());
    let sub_point = verify_column_relation_trace(
        b,
        &mut ch,
        w_log,
        &target,
        &terminal.point,
        &sub_e_terms,
        &fixed,
        &sub_e,
    );
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&sub_native).iter().zip(sub_e.final_values.iter()) {
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
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
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
    assert_eq!(np_cursor, np.len(), "leaf-union pending lockstep");

    let stride = chain.stride();
    let mut digest_wires = Vec::with_capacity(tile_digests.len());
    for (t, dig) in tile_digests.iter().enumerate() {
        let slot = t * stride + chain.digest_slot();
        let (pt_lin, pt_nat) = slot_point(slot, w_log);
        let mut wires: [LinExpr; 2] = [LinExpr::zero(), LinExpr::zero()];
        for lane in 0..2 {
            let value = LinExpr::from_wire(b.alloc_f128(dig[lane]));
            out.push(Claim {
                slice: base + 2 + lane,
                point: pt_lin.clone(),
                value: value.clone(),
                native_point: pt_nat.clone(),
                native_value: dig[lane],
            });
            wires[lane] = value;
        }
        digest_wires.push(wires);
    }
    (out, digest_wires)
}

// ===========================================================================
// Basis + small helpers (private; shadow the proven gate).
// ===========================================================================

fn phi(bl: Block128) -> F128 {
    flat_of_tower_u128(bl.0)
}

fn lanes_flat(d: &[u8; 32]) -> [F128; 2] {
    [
        phi(Block128::from(u128::from_le_bytes(d[..16].try_into().unwrap()))),
        phi(Block128::from(u128::from_le_bytes(d[16..].try_into().unwrap()))),
    ]
}

/// The tx-root region handoff: every user tx's body-hash Merkle path to the
/// header `tx_root`, as ONE walk-B TAG_COMPRESS leg. Entries are the SPINE
/// tx-hash wires (the leaf closure); the root is the header `tx_root` wire
/// pair (the root closure); direction bits are the CONSTANT leaf-index bits
/// and the last real path's right-hand siblings are the zero-subtree padding
/// constants — both become const cell pins on the committed D/SIB cells.
pub struct TxRootRegionData {
    /// The padded tx-tree depth (class data:
    /// `1 << depth = n_txs.next_power_of_two().max(2)`).
    pub depth: usize,
    /// The header `tx_root` statement wires — every path's expected root.
    pub root_w: [LinExpr; 2],
    pub root_flat: [F128; 2],
    /// One path per user tx, in tx order (path `j`'s leaf position is `j`).
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
/// plus the statement wires the leg pins bind (entry = the paired slot-leaf /
/// guard-bucket digest wires; root = the expected-root statement wires).
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
    assert!(real.len() <= cap, "es leg chunk exceeds the per-block capacity");
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
    let family = MerklePathFamily { depth, n_paths: cap };
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

fn eq_tensor_tower(point: &[Block128]) -> Vec<Block128> {
    let mut t = vec![Block128::ONE; 1usize << point.len()];
    for (i, slot) in t.iter_mut().enumerate() {
        let mut e = Block128::ONE;
        for (ll, &pp) in point.iter().enumerate() {
            e = e * if (i >> ll) & 1 == 1 { pp } else { Block128::ONE + pp };
        }
        *slot = e;
    }
    t
}

fn alloc_column_slice(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> (WitnessSlice, Vec<LinExpr>) {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    let wires: Vec<LinExpr> = col.iter().map(|&v| LinExpr::from_wire(b.alloc_f128(v))).collect();
    for _ in col.len()..block {
        b.alloc_f128(F128::ZERO);
    }
    (WitnessSlice { log2_len, index }, wires)
}

/// The boolean point selecting slot `s` in `w_log` coordinates.
fn slot_point(s: usize, w_log: usize) -> (Vec<LinExpr>, Vec<F128>) {
    let lin = (0..w_log)
        .map(|bb| LinExpr::constant(if (s >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO }))
        .collect();
    let nat = (0..w_log).map(|bb| if (s >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO }).collect();
    (lin, nat)
}

/// The committed cell at `slot` of `slice`, as a raw wire read. Bound by the
/// column's walk opening (Stage 2: pin an algebra wire to a cell instead of
/// emitting a per-cell opening claim — an R1CS row, not a link-IO lane).
fn slot_cell(slice: &WitnessSlice, slot: usize) -> LinExpr {
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
fn common_period_pattern(
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
fn common_period_ones(offset: usize, len: usize, block_log: usize) -> FixedPattern {
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

/// `basis + ONE + r` factor of `tensor_high_fold_pair`, char-2 (local twin of
/// the private `auth_pcs::tensor_high_fold_pair_trace`).
/// High-fold pair fold `s1 + s0·(r + twiddle)`, where the additive-NTT
/// twiddle is `flat_of(2^(coset + layer_log − 1)) XOR 1`. The fold coset is
/// `leaf_index >> (layer_log − 1)` — the RS-code coset, which never folds, so
/// it is exactly `LOG_RATE` bits. Baking the twiddle as a native constant made
/// the mul gate's constant term depend on the query position and drifted the
/// matrix between blocks; here the coset is a witness-bit mux over the
/// `2^LOG_RATE` protocol-constant twiddles, so the constraint is class-fixed
/// and the block-dependence lives only in the boolean `coset_bits` values.
/// `coset_bits` are the position bits at index `layer_log−1 ..` (LSB first),
/// threaded from the transcript-bound query decomposition.
fn tensor_high_fold_pair_trace(
    b: &mut FieldR1csBuilder,
    r: &LinExpr,
    layer_log: usize,
    coset_bits: &[LinExpr],
    s0: &LinExpr,
    s1: &LinExpr,
) -> LinExpr {
    // eq tensor of the coset bits (2^LOG_RATE entries: entry c = eq(bits, c)).
    let mut tensor = vec![LinExpr::constant(F128::ONE)];
    for bit in coset_bits {
        let his: Vec<LinExpr> = tensor.iter().map(|t| mul(b, t, bit)).collect();
        let mut next = Vec::with_capacity(tensor.len() * 2);
        for (t, h) in tensor.iter().zip(his.iter()) {
            next.push(t.add(h));
        }
        next.extend(his);
        tensor = next;
    }
    // twiddle = Σ_c eq(coset_bits, c) · [flat_of(2^(c + layer_log − 1)) XOR 1].
    let mut twiddle = LinExpr::zero();
    for (c, t) in tensor.iter().enumerate() {
        let basis_idx = c + layer_log - 1;
        let tw = flat_of(Block128::from((1u128 << basis_idx) ^ 1));
        twiddle = twiddle.add(&t.scale(tw));
    }
    let factor = r.add(&twiddle);
    s1.add(&mul(b, s0, &factor))
}

/// Mirror `high_pair_leaf_index` on a query's position bit wires: drop the
/// parity bit (index `layer_log − 1` of the low `layer_log` bits) and keep the
/// rest in order. Pure wire reindexing (no constraints) — it stays aligned
/// with the native `high_pair_leaf_index` applied to the same index, so the
/// bit at any position of the result is the transcript-bound query bit.
fn high_pair_leaf_index_bits(bits: &[LinExpr], layer_log: usize) -> Vec<LinExpr> {
    let mut out = bits[..layer_log - 1].to_vec();
    out.extend_from_slice(&bits[layer_log..]);
    out
}

/// `arr[idx]` selected by the witness bits of `idx` (LSB first):
/// `Σ_c eq(bits, c)·arr[c]`. Reads every `arr` wire with a class-fixed
/// coefficient structure — the block-dependence lives only in the boolean bit
/// values — so it replaces a native `arr[native_idx]` read whose selected wire
/// (and thus the constraint's column) drifts with the query position.
/// `arr.len()` must equal `2^bits.len()`.
fn select_by_bits(b: &mut FieldR1csBuilder, bits: &[LinExpr], arr: &[LinExpr]) -> LinExpr {
    debug_assert_eq!(arr.len(), 1usize << bits.len(), "select_by_bits arity");
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
struct UnionNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    /// ONE tiled exposure proof over all K source trees (see [`ExpoTiledSpec`]).
    expo_proof: ColumnRelationProof,
    pending: Vec<(usize, Vec<F128>, F128)>,
    /// The 4 re-pointed exposure claims (KID0/1, C0/1), flat in tx count.
    expo_pending: Vec<(usize, Vec<F128>, F128)>,
    /// ONE gated tiled exposure over all spine trees + its 4 re-pointed
    /// claims (present iff the spine families ride this union).
    spine_expo_proof: Option<ColumnRelationProof>,
    spine_expo_pending: Vec<(usize, Vec<F128>, F128)>,
}

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
        assert_eq!(self.tree_base % (1usize << start), 0, "spine tree base alignment");
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

/// The tiled source-tree exposure binding into the SHARED walk-A columns. The K
/// trees' `kid_lo` (period `2^(st_wlog-1)`) and full `C` (period `2^st_wlog`) are
/// concatenated in tx order into ONE relation domain; `Window(C,1,1)[tx·2L+local]
/// = C[tx·4L+2local+1]` tiles because C's period is 2× KID's. ONE sumcheck
/// discharges all trees and its 4 terminal claims (KID0/1 plain, C0/1 via window)
/// re-point into the shared walk-A KID/C columns at zero-bit-inserted points
/// `[rho_local, ZERO, zeros(block_log_a − st_wlog), rho_tx]` — flat (O(1)) in tx
/// count. `tx_log` = `log2` of the power-of-two tree count (= walk-A's tx bits).
struct ExpoTiledSpec {
    kid_meta: [usize; 2],
    c_meta: [usize; 2],
    tx_log: usize,
}

fn union_native_terms(
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    alpha: F128,
) -> Vec<RelationTerm> {
    let mut terms = source_tree_substitution_terms(st_refs, alpha);
    for lr in leaf_refs {
        terms.extend(source_leaf_substitution_terms(lr, alpha));
    }
    // Exact-state sponge family: its own substitution reads IN0/IN1 PLAINLY
    // (every slot of the standalone family absorbs); in the union those
    // terms would fire inside other families' slots, so any term without a
    // Fixed factor is gated by the family's region-ones pattern — the same
    // discipline the walk-B merkle union applies. All its committed refs
    // (IN0/IN1, C0..C3) are already claimed by the wallet leaf families, so
    // the union's claimed-ref set (and claim count) is unchanged.
    if let Some((sr, region)) = es_sponge {
        let mut t = sponge_leaf_substitution_terms(sr, alpha);
        for term in t.iter_mut() {
            if !term.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
                term.factors.insert(0, ColRef::Fixed(*region));
            }
        }
        terms.extend(t);
    }
    // Spine families: the tree is the SOURCE-TREE shape on the shared
    // CODE/KID/C columns with its own patterns (LEAFODD ≡ 0, so the
    // `LEAFODD·CODE` terms vanish identically); the tile is the region-gated
    // sponge shape. Every committed ref is already claimed above, so the
    // union's claimed-ref set (and claim count) is again unchanged.
    if let Some(sp) = spine {
        terms.extend(source_tree_substitution_terms(&sp.tree_refs, alpha));
        let mut t = sponge_leaf_substitution_terms(&sp.tile_refs, alpha);
        for term in t.iter_mut() {
            if !term.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
                term.factors.insert(0, ColRef::Fixed(sp.tile_region));
            }
        }
        terms.extend(t);
    }
    terms
}

#[allow(clippy::too_many_arguments)]
fn run_union_native(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    spine_expo_cols: Option<&[&[F128]; 4]>,
    w_log: usize,
    expo: &ExpoTiledSpec,
    expo_cols: &[&[F128]; 4],
    expo_wlog: usize,
    block_log_a: usize,
) -> UnionNative {
    assert_eq!(spine.is_some(), spine_expo_cols.is_some(), "spine expo columns");
    let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(DOMAIN);
    let mut ch_v = FsLaneChallenger::new(DOMAIN);
    let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&st_refs.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns { committed, internal: &internal, fixed },
        &mut ch_p,
    );
    let sel_point =
        verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, fixed, &sel_proof, &mut ch_v)
            .expect("native selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms).iter().zip(sel_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }

    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal = verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_native_terms(st_refs, leaf_refs, es_sponge, spine, alpha);
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
        &RelationColumns { committed, internal: &[], fixed },
        &mut ch_p,
    );
    let sub_point =
        verify_column_relation(w_log, target, &terminal.point, &sub_terms, fixed, &sub_proof, &mut ch_v)
            .expect("native substitution");
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
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

    // ONE tiled exposure over all K source trees. The tiled KID/C columns
    // (kid_lo period 2L, full C period 4L) discharge in a single sumcheck;
    // `Window(C,1,1)` tiles because C's period is 2× KID's. The 4 terminal claims
    // re-point into the shared walk-A KID/C columns via zero-bit insertion
    // `[rho_local, ZERO, zeros(block_pad), rho_tx]` (window offset bits prepended
    // for C) — one claim per lane, flat in tx count.
    let expo_tiled_wlog = expo.tx_log + (expo_wlog - 1);
    let block_pad = block_log_a - expo_wlog;
    let gamma = ch_p.sample_f128();
    assert_eq!(gamma, ch_v.sample_f128());
    let expo_terms = source_tree_exposure_terms([0, 1], [2, 3], gamma);
    let rho_e = ch_p.sample_f128_vec(expo_tiled_wlog);
    let _ = ch_v.sample_f128_vec(expo_tiled_wlog);
    let (expo_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_e,
        &expo_terms,
        &RelationColumns { committed: expo_cols, internal: &[], fixed: &[] },
        &mut ch_p,
    );
    let expo_point =
        verify_column_relation(expo_tiled_wlog, F128::ZERO, &rho_e, &expo_terms, &[], &expo_proof, &mut ch_v)
            .expect("native tiled exposure");
    let (rho_local, rho_tx) = expo_point.split_at(expo_wlog - 1);
    let mut expo_pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();
    for (r, v) in claimed_refs(&expo_terms).iter().zip(expo_proof.final_values.iter()) {
        match r {
            ColRef::Committed(ll) => {
                let mut pt = rho_local.to_vec();
                pt.push(F128::ZERO);
                pt.extend(std::iter::repeat(F128::ZERO).take(block_pad));
                pt.extend_from_slice(rho_tx);
                expo_pending.push((expo.kid_meta[*ll], pt, *v));
            }
            ColRef::Window { col, stride_log, offset } => {
                let mut pt = window_discharge_point(*offset, *stride_log, rho_local);
                pt.extend(std::iter::repeat(F128::ZERO).take(block_pad));
                pt.extend_from_slice(rho_tx);
                expo_pending.push((expo.c_meta[*col - 2], pt, *v));
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
            &RelationColumns { committed: se_cols, internal: &[], fixed: &expo_fixed },
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
        for (r, v) in claimed_refs(&expo_terms).iter().zip(proof.final_values.iter()) {
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
        expo_proof,
        pending,
        expo_pending,
        spine_expo_proof,
        spine_expo_pending,
    }
}

/// One source-tree-shaped trace term block (shared by the wallet tree and
/// the spine tree, which differ only in their pattern indices).
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
            terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(st_refs.iv[j - 2])] });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(st_refs.odd_int), ColRef::CommittedShift(st_refs.c[j])],
        });
    }
}

/// One region-gated sponge-shaped trace term block (shared by the
/// exact-state sponge tiles and the spine leaf/wrap tile).
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
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
) -> Vec<RelationTermTrace> {
    let mut terms = Vec::new();
    tree_trace_terms(m, st_refs, &mut terms);
    for lr in leaf_refs {
        for i in 0..2 {
            let in_col = ColRef::Committed(lr.in_[i]);
            let c_sh = ColRef::CommittedShift(lr.c[i]);
            let c_sh2 = ColRef::CommittedShift2(lr.c[i]);
            for factors in [
                vec![ColRef::Fixed(lr.hp), in_col],
                vec![ColRef::Fixed(lr.even), c_sh2],
                vec![ColRef::Fixed(lr.odd), c_sh],
                vec![ColRef::Fixed(lr.odd), c_sh2],
            ] {
                terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
            }
        }
        for j in 2..STATE_SIZE {
            terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(lr.iv[j - 2])] });
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(lr.odd), ColRef::CommittedShift(lr.c[j])],
            });
        }
    }
    // Exact-state sponge family — the line-by-line shadow of the GATED
    // `sponge_leaf_substitution_terms` (region-ones inserted on the plain IN
    // reads; the ODD-gated carries and IV patterns carry their own gate).
    if let Some((sr, region)) = es_sponge {
        gated_sponge_trace_terms(m, sr, *region, &mut terms);
    }
    // Spine families — the shadow of the native spine blocks (tree shape on
    // its own patterns, then the region-gated tile).
    if let Some(sp) = spine {
        tree_trace_terms(m, &sp.tree_refs, &mut terms);
        gated_sponge_trace_terms(m, &sp.tile_refs, sp.tile_region, &mut terms);
    }
    terms
}

fn union_ref_terms(
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
) -> Vec<RelationTerm> {
    union_native_terms(st_refs, leaf_refs, es_sponge, spine, F128::ONE)
}

#[allow(clippy::too_many_arguments)]
fn discharge_union(
    b: &mut FieldR1csBuilder,
    fixed: &[FixedPattern],
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    w_log: usize,
    expo_wlog: usize,
    block_log_a: usize,
    expo: &ExpoTiledSpec,
    native: &UnionNative,
) -> Vec<Claim> {
    let mut ch = FsChannelTrace::new(b, DOMAIN);
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut cur = 0usize;
    let zero = LinExpr::zero();

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_terms: Vec<RelationTermTrace> = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_terms.push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Committed(st_refs.c[j])] });
        sel_terms.push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Internal(j)] });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point = verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_terms, fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(&st_refs.c, F128::ONE));
    let mut gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    for (r, v) in sel_claimed.iter().zip(sel_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim { slice: *col, point: sel_point.clone(), value: v.clone(), native_point: npt.clone(), native_value: *nval });
            }
            ColRef::Internal(j) => gv[*j] = v.clone(),
            _ => unreachable!(),
        }
    }

    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let (m, ap) = mds_alpha_weights(b, &alpha);
    let sub_terms = union_trace_terms(&m, st_refs, leaf_refs, es_sponge, spine);
    let ref_terms = union_ref_terms(st_refs, leaf_refs, es_sponge, spine);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&ref_terms).len());
    let sub_point = verify_column_relation_trace(b, &mut ch, w_log, &target, &terminal.point, &sub_terms, fixed, &sub_e);
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&ref_terms).iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim { slice: *col, point: sub_point.clone(), value: v.clone(), native_point: npt.clone(), native_value: *nval });
            }
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (shift_log, _col, ns) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *shift_log, &se);
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim { slice: *col, point: pt, value: se.final_value.clone(), native_point: npt.clone(), native_value: *nval });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(shift_cursor, native.shifts.len(), "all shifts consumed");
    assert_eq!(cur, np.len(), "union pending lockstep");

    // ONE tiled source-tree exposure (mirror of `run_union_native`). The 4
    // terminal claims re-point into walk-A KID/C by splitting the tiled point into
    // `[rho_local | rho_tx]` and inserting `ZERO + zeros(block_pad)` between them
    // (window offset bits prepended for C) — flat (O(1)) in tx count.
    let expo_ref = source_tree_exposure_terms([0, 1], [2, 3], F128::ZERO);
    let expo_tiled_wlog = expo.tx_log + (expo_wlog - 1);
    let block_pad = block_log_a - expo_wlog;
    let gamma = ch.sample_f128(b);
    let mut gp = LinExpr::constant(F128::ONE);
    let mut expo_terms: Vec<RelationTermTrace> = Vec::new();
    for i in 0..2 {
        gp = mul(b, &gp, &gamma);
        expo_terms.push(RelationTermTrace { coeff: gp.clone(), factors: vec![ColRef::Committed(i)] });
        expo_terms.push(RelationTermTrace {
            coeff: gp.clone(),
            factors: vec![ColRef::Window { col: 2 + i, stride_log: 1, offset: 1 }],
        });
    }
    let rho_e = ch.sample_f128_vec(b, expo_tiled_wlog);
    let expo_e =
        ColumnRelationProofTrace::alloc(b, &native.expo_proof, expo_tiled_wlog, claimed_refs(&expo_ref).len());
    let expo_point = verify_column_relation_trace(b, &mut ch, expo_tiled_wlog, &zero, &rho_e, &expo_terms, &[], &expo_e);
    let (rho_local, rho_tx) = expo_point.split_at(expo_wlog - 1);
    let mut ec = 0usize;
    for (r, v) in claimed_refs(&expo_ref).iter().zip(expo_e.final_values.iter()) {
        let (col, npt, nval) = &native.expo_pending[ec];
        ec += 1;
        match r {
            ColRef::Committed(_) => {
                let mut pt = rho_local.to_vec();
                pt.push(LinExpr::constant(F128::ZERO));
                for _ in 0..block_pad {
                    pt.push(LinExpr::constant(F128::ZERO));
                }
                pt.extend_from_slice(rho_tx);
                out.push(Claim { slice: *col, point: pt, value: v.clone(), native_point: npt.clone(), native_value: *nval });
            }
            ColRef::Window { offset, stride_log, .. } => {
                let mut pt: Vec<LinExpr> = (0..*stride_log)
                    .map(|jb| LinExpr::constant(if (offset >> jb) & 1 == 1 { F128::ONE } else { F128::ZERO }))
                    .collect();
                pt.extend_from_slice(rho_local);
                for _ in 0..block_pad {
                    pt.push(LinExpr::constant(F128::ZERO));
                }
                pt.extend_from_slice(rho_tx);
                out.push(Claim { slice: *col, point: pt, value: v.clone(), native_point: npt.clone(), native_value: *nval });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(ec, native.expo_pending.len(), "exposure pending lockstep");

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
                    ColRef::Window { col: 2 + i, stride_log: 1, offset: 1 },
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
        for (r, v) in claimed_refs(&expo_ref).iter().zip(expo_e.final_values.iter()) {
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
        assert_eq!(ec2, native.spine_expo_pending.len(), "spine exposure pending lockstep");
    }
    out
}

// ===========================================================================
// WALK B — the merkle-union.
// ===========================================================================
fn union_merkle_refs(fixed_base: usize) -> MerkleFamilyRefs {
    MerkleFamilyRefs {
        e: [6, 7],
        sib: [8, 9],
        d: 10,
        c: std::array::from_fn(|i| 2 + i),
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
struct MerkleLeg {
    family: MerklePathFamily,
    refs: MerkleFamilyRefs,
    region: usize,
    committed_roots: Vec<[F128; 2]>,
    entry_wires: Vec<[LinExpr; 2]>,
    pair_entry_map: Option<Vec<usize>>,
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

fn union_bool_terms(legs: &[MerkleLeg]) -> Vec<RelationTerm> {
    let mut t = Vec::new();
    for leg in legs {
        t.extend(merkle_booleanity_terms(&leg.refs));
    }
    t
}

fn union_sub_terms_native(
    pair_refs: &PairLeafRefs,
    region_pair: usize,
    legs: &[MerkleLeg],
    alpha: F128,
) -> Vec<RelationTerm> {
    let mut terms = pair_leaf_substitution_terms(pair_refs, alpha);
    for t in terms.iter_mut() {
        t.factors.insert(0, ColRef::Fixed(region_pair));
    }
    for leg in legs {
        let mut m = merkle_substitution_terms(&leg.refs, alpha);
        for t in m.iter_mut() {
            if !t.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
                t.factors.insert(0, ColRef::Fixed(leg.region));
            }
        }
        terms.extend(m);
    }
    terms
}

fn union_bool_terms_trace(legs: &[MerkleLeg]) -> Vec<RelationTermTrace> {
    union_bool_terms(legs)
        .iter()
        .map(|t| RelationTermTrace { coeff: LinExpr::constant(t.coeff), factors: t.factors.clone() })
        .collect()
}

fn union_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    pair_refs: &PairLeafRefs,
    region_pair: usize,
    legs: &[MerkleLeg],
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let (m, ap) = mds_alpha_weights(b, alpha);
    let mut terms: Vec<RelationTermTrace> = Vec::new();

    for i in 0..2 {
        terms.push(RelationTermTrace {
            coeff: m[i].clone(),
            factors: vec![ColRef::Fixed(region_pair), ColRef::Committed(pair_refs.in_[i])],
        });
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
                terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
            }
        }
        for j in 2..STATE_SIZE {
            let c_sh = ColRef::CommittedShift(refs.c[j]);
            terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![region, c_sh] });
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

struct MerkleUnionNative {
    bool_proof: ColumnRelationProof,
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<(usize, Vec<F128>, F128)>,
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
        cb[2 + j][rng.clone()].copy_from_slice(&cols.c[j][0..n_slots]);
        s0b[j][rng.clone()].copy_from_slice(&cols.s0[j][0..n_slots]);
        soutb[j][rng.clone()].copy_from_slice(&cols.s_out[j][0..n_slots]);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_merkle_union_native(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    pair_refs: &PairLeafRefs,
    region_pair: usize,
    legs: &[MerkleLeg],
    w_log: usize,
    domain: &[u8],
) -> MerkleUnionNative {
    let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

    let bool_terms = union_bool_terms(legs);
    let rho_b = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (bool_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_b,
        &bool_terms,
        &RelationColumns { committed, internal: &[], fixed },
        &mut ch_p,
    );
    let bool_point =
        verify_column_relation(w_log, F128::ZERO, &rho_b, &bool_terms, fixed, &bool_proof, &mut ch_v)
            .expect("native merkle-union booleanity");
    for (r, v) in claimed_refs(&bool_terms).iter().zip(bool_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, bool_point.clone(), *v)),
            _ => unreachable!(),
        }
    }

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&pair_refs.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns { committed, internal: &internal, fixed },
        &mut ch_p,
    );
    let sel_point =
        verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, fixed, &sel_proof, &mut ch_v)
            .expect("native merkle-union selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms).iter().zip(sel_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }

    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native merkle walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_sub_terms_native(pair_refs, region_pair, legs, alpha);
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
        &RelationColumns { committed, internal: &[], fixed },
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
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
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
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native merkle-union lockstep");
    MerkleUnionNative { bool_proof, sel_proof, walk_proof, sub_proof, shifts, pending }
}

#[allow(clippy::too_many_arguments)]
fn discharge_merkle_union(
    b: &mut FieldR1csBuilder,
    fixed: &[FixedPattern],
    pair_refs: &PairLeafRefs,
    region_pair: usize,
    legs: &[MerkleLeg],
    w_log: usize,
    native: &MerkleUnionNative,
    pair_digest_vals: &[[F128; 2]],
    pair_slots: &[usize],
    domain: &[u8],
) -> (Vec<Claim>, Vec<(usize, usize, LinExpr)>, Vec<[LinExpr; 2]>) {
    let mut ch = FsChannelTrace::new(b, domain);
    let mut out: Vec<Claim> = Vec::new();
    // Stage 2: the per-cell reads/pins (pair-leaf digests, leg entries, leg
    // roots) resolve to pin_eq of the wire to the committed cell -- R1CS rows,
    // not link-IO claims. Every column is opened by this walk's booleanity /
    // selection / substitution (random point), so the cells are bound.
    let mut cell_pins: Vec<(usize, usize, LinExpr)> = Vec::new();
    let np = &native.pending;
    let mut cur = 0usize;
    let zero = LinExpr::zero();

    let bool_ref = union_bool_terms(legs);
    let n_bool = claimed_refs(&bool_ref).len();
    let rho_b = ch.sample_f128_vec(b, w_log);
    let bool_e = ColumnRelationProofTrace::alloc(b, &native.bool_proof, w_log, n_bool);
    let bool_terms_e = union_bool_terms_trace(legs);
    let bool_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho_b, &bool_terms_e, fixed, &bool_e);
    for (r, v) in claimed_refs(&bool_ref).iter().zip(bool_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim {
                    slice: *col,
                    point: bool_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_terms: Vec<RelationTermTrace> = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Committed(pair_refs.c[j])],
        });
        sel_terms.push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Internal(j)] });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_terms, fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(&pair_refs.c, F128::ONE));
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

    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let (sub_terms, ap) = union_sub_terms_trace(b, pair_refs, region_pair, legs, &alpha);
    let ref_terms = union_sub_terms_native(pair_refs, region_pair, legs, F128::ONE);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e =
        ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&ref_terms).len());
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
    for (r, v) in claimed_refs(&ref_terms).iter().zip(sub_e.final_values.iter()) {
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
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *shift_log, &se);
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
    assert_eq!(shift_cursor, native.shifts.len(), "merkle-union shifts consumed");
    assert_eq!(cur, np.len(), "merkle-union pending lockstep");

    // Pair-leaf per-tile digest claims (feed the 3i Merkle entries).
    let mut pair_digest_wires = Vec::with_capacity(pair_digest_vals.len());
    for (t, dig) in pair_digest_vals.iter().enumerate() {
        let mut wires: [LinExpr; 2] = [LinExpr::zero(), LinExpr::zero()];
        for lane in 0..2 {
            let value = LinExpr::from_wire(b.alloc_f128(dig[lane]));
            cell_pins.push((pair_refs.c[lane], pair_slots[t], value.clone()));
            wires[lane] = value;
        }
        pair_digest_wires.push(wires);
    }

    // Per-leg entry pins (E == shared leaf digest wire) + recomputed-root pins
    // (C0/C1 at the root slot == the FS-OBSERVED root wire) -- both pin_eq, no
    // IO claims (flat in tx count; see the per-path block below).
    for leg in legs {
        let root_slot_local = 2 * (leg.family.depth - 1) + 1;
        for path in 0..leg.path_slots.len() {
            let entry_wire: [LinExpr; 2] = match &leg.pair_entry_map {
                Some(map) => pair_digest_wires[map[path]].clone(),
                None => leg.entry_wires[path].clone(),
            };
            let entry_slot = leg.path_slots[path];
            for lane in 0..2 {
                cell_pins.push((leg.refs.e[lane], entry_slot, entry_wire[lane].clone()));
            }
            // TRANSCRIPT-BINDING (flat): the recomputed-root column cell at
            // `root_slot` is `pin_eq`'d to the FS-OBSERVED root wire
            // (`leg.root_wires`, absorbed into the channel BEFORE the query draw).
            // The C column is opened at a random point by the Merkle walk
            // (selection + compress shift discharges bind its whole MLE), so the
            // cell is bound; the pin is an R1CS ROW, not an IO claim -- it keeps
            // the auth root FS-bound WITHOUT growing the claim vector (flat in tx
            // count). A prover cannot authenticate a path against a root chosen
            // after the query positions are known: the walk-recomputed root is
            // forced == the transcript-seeded root.
            let root_slot = leg.path_slots[path] + root_slot_local;
            for lane in 0..2 {
                assert_eq!(leg.recomputed_roots[path][lane], leg.committed_roots[path][lane]);
                cell_pins.push((leg.refs.c[lane], root_slot, leg.root_wires[path][lane].clone()));
            }
        }
    }

    (out, cell_pins, pair_digest_wires)
}

/// Drive the REAL noid_fri::Channel through the whole `verify_mixed_opening`
/// transcript to the two `gen_compact_queries` draws (native cross-check).
fn derive_queries(
    proof: &AuthMleOpeningProof,
    primary_point: &[Block128],
    num_queries: usize,
) -> (Vec<usize>, Vec<usize>) {
    let commitment = &proof.commitment;
    let opening = &proof.opening;
    let log_n = commitment.log_rows;
    let tau = COMPACT_TAU.min(log_n);
    let fri = &opening.fri_proof;
    let src = &opening.source_proof;
    let (right, _left) = primary_point.split_at(log_n - tau);
    let n_rounds = right.len();

    let mut channel = Channel::new();
    noid_fri_binius::absorb_cap(&mut channel, &commitment.cap);
    channel.observe_field_elem(Block128::from(MIXED_OPEN_TAG));
    channel.observe_field_elems(&opening.all_openings);
    let _gamma = channel.get_random_point();
    let batched_claim = opening.all_openings[0];
    channel.observe_field_elems(primary_point);
    channel.observe_field_elem(batched_claim);
    let _beta = channel.get_random_points(tau);
    for round in 0..n_rounds {
        let [c0, c1] = fri.sum_check_oracles[round];
        channel.observe_field_elem(c0);
        channel.observe_field_elem(c1);
        let depth = compute_round_depth(n_rounds, round);
        channel.observe_vector_commitment(&VectorCommitment { root: fri.fri_roots[round], depth });
        let _r = channel.get_random_point();
    }
    channel.observe_field_elems(&fri.final_codeword);
    channel.observe_field_elem(Block128::from(MIXED_SOURCE_BINDING_TAG));
    channel.observe_field_elems(&src.h_evals);
    for (i, root) in src.folded_roots.iter().enumerate() {
        let layer_log = log_n - 1 - i;
        channel.observe_vector_commitment(&VectorCommitment {
            root: *root,
            depth: high_pair_tree_depth(layer_log),
        });
    }
    let source_queries = gen_compact_queries(&mut channel, log_n + LOG_RATE, num_queries);
    let fri_queries = gen_compact_queries(&mut channel, n_rounds + LOG_RATE, num_queries);
    (source_queries, fri_queries)
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
struct DuplexUnion {
    committed: [Vec<F128>; 6],
    s0: [Vec<F128>; STATE_SIZE],
    s_out: [Vec<F128>; STATE_SIZE],
    fixed: Vec<FixedPattern>,
    refs: DuplexFamilyRefs,
    layout: DuplexLayout,
    w_log: usize,
    block_log: usize,
    /// One squeezed-challenge stream per real tx (schedule order).
    challenges: Vec<Vec<F128>>,
}

/// Tile `data.len()` transactions' duplex channels into ONE walk-C domain at a
/// common per-tx block period. `data[t]` is tx `t`'s absorbed-data stream (flat,
/// length `layout.n_data`). The tile count is padded to a power of two with
/// CANONICAL GHOST channel blocks (IV-seeded, zero-data channels) — NOT
/// `perm([0;4])` ghost slots: the duplex substitution's leading carry term is
/// ungated, so every block must be a valid IV-seeded chain (the START pattern
/// cancels the cross-block carry in char 2, re-seeding each block).
fn build_duplex_union(layout: &DuplexLayout, iv_flat: [F128; 2], data: &[Vec<F128>]) -> DuplexUnion {
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
    }
}

struct DuplexUnionNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<(usize, Vec<F128>, F128)>,
}

/// Native discharge of the whole channel union in ONE walk (mirror of
/// `run_leaf_union_native` with the duplex family's terms).
fn run_duplex_union_native(u: &DuplexUnion, domain: &[u8]) -> DuplexUnionNative {
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
        &RelationColumns { committed: &committed, internal: &internal, fixed },
        &mut ch_p,
    );
    let sel_point =
        verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, fixed, &sel_proof, &mut ch_v)
            .expect("native duplex selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms).iter().zip(sel_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }
    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(&u.s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native duplex walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = duplex_substitution_terms(refs, alpha);
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
        &RelationColumns { committed: &committed, internal: &[], fixed },
        &mut ch_p,
    );
    let sub_point =
        verify_column_relation(w_log, target, &terminal.point, &sub_terms, fixed, &sub_proof, &mut ch_v)
            .expect("native duplex substitution");
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
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
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native duplex-union lockstep");
    DuplexUnionNative { sel_proof, walk_proof, sub_proof, shifts, pending }
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

/// Discharge the shared channel union in-trace (mirror of `discharge_leaf_union`
/// for the duplex family). Column claims are offset by `base` in the caller's
/// global slice table. Returns the pending terminal claims on the A/C columns.
fn discharge_duplex_union(
    b: &mut FieldR1csBuilder,
    u: &DuplexUnion,
    domain: &[u8],
    native: &DuplexUnionNative,
    base: usize,
) -> Vec<Claim> {
    let refs = &u.refs;
    let fixed = &u.fixed;
    let w_log = u.w_log;
    let mut ch = FsChannelTrace::new(b, domain);
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut np_cursor = 0usize;
    let zero = LinExpr::zero();

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_e_terms = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_e_terms
            .push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Committed(refs.c[j])] });
        sel_e_terms
            .push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Internal(j)] });
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
    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let sub_native = duplex_substitution_terms(refs, F128::ONE);
    let (sub_e_terms, ap) = duplex_sub_terms_trace(b, refs, &alpha);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e =
        ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&sub_native).len());
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
    for (r, v) in claimed_refs(&sub_native).iter().zip(sub_e.final_values.iter()) {
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
fn bind_duplex_challenges(
    u: &DuplexUnion,
    t: usize,
    base: usize,
    chal_wires: &[LinExpr],
    out: &mut Vec<Claim>,
) {
    let per_tx = 1usize << u.block_log;
    assert_eq!(chal_wires.len(), u.layout.challenges.len(), "challenge wire count");
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
fn duplex_data_positions(layout: &DuplexLayout) -> Vec<(usize, usize)> {
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
struct SubChannel {
    layout: DuplexLayout,
    iv_flat: [F128; 2],
}

/// The 7 duplex fixed patterns (`start, abs0, abs1, const0..const3`) over the
/// combined per-tx period `N·S`, with sub-channel `i` placed at offset `i·S`.
/// Mirrors `duplex_fixed_patterns` per sub-block: `start[i·S]=1` (the carry reset),
/// the capacity IV on `const2/const3` at `i·S`, and each real slot's absorb
/// selectors / rate constants at `i·S + sl`. Ghost sub-block slots (past a sub's
/// real length) carry START=0 and no constants — they just continue the chain, and
/// `build_duplex_columns` fills the matching continuing-chain tail per sub-block.
#[cfg_attr(not(test), allow(dead_code))]
fn combined_duplex_fixed_patterns(subs: &[SubChannel], s_log: usize) -> Vec<FixedPattern> {
    let s = 1usize << s_log;
    let per_tx = subs.len() * s;
    let block_log = per_tx.trailing_zeros() as usize;
    let mut start = vec![F128::ZERO; per_tx];
    let mut abs: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; per_tx]);
    let mut consts: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; per_tx]);
    for (i, sub) in subs.iter().enumerate() {
        let off = i * s;
        assert!(sub.layout.slots.len() <= s, "sub schedule exceeds the common S");
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
fn combined_duplex_layout(subs: &[SubChannel], s_log: usize) -> DuplexLayout {
    let s = 1usize << s_log;
    let per_tx = subs.len() * s;
    let mut slots = vec![DuplexSlot { lanes: [None, None] }; per_tx];
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
    DuplexLayout { slots, challenges, n_data: data_off }
}

/// Each data lane's `(slot, lane)` in the combined per-tx block, in the flattened
/// `[sub0 data ++ sub1 data ++ ...]` order — sub `i`'s `duplex_data_positions` with
/// slot shifted by `i·S`. The per-tx algebra reads each channel's absorbed data at
/// these positions; agrees with `duplex_data_positions(&combined_duplex_layout(..))`.
#[cfg_attr(not(test), allow(dead_code))]
fn combined_duplex_data_positions(subs: &[SubChannel], s_log: usize) -> Vec<(usize, usize)> {
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
fn build_combined_duplex_union(subs: &[SubChannel], data: &[Vec<Vec<F128>>]) -> DuplexUnion {
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
        assert_eq!(row.len(), n_real, "data row {t} width must equal the sub-channel count");
        for (i, stream) in row.iter().enumerate() {
            assert_eq!(stream.len(), subs[i].layout.n_data, "data[{t}][{i}] length");
        }
    }

    // Pad N up to a power of two with canonical ghost sub-channels (an empty
    // schedule seeds a pure zero-IV chain in its S-block — no absorbs, no
    // challenges). For the N=2 wallet use this is a no-op.
    let ghost = SubChannel {
        layout: DuplexLayout { slots: Vec::new(), challenges: Vec::new(), n_data: 0 },
        iv_flat: [F128::ZERO, F128::ZERO],
    };
    let subs_padded: Vec<SubChannel> =
        (0..n).map(|i| if i < n_real { subs[i].clone() } else { ghost.clone() }).collect();

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges: Vec<Vec<F128>> = Vec::with_capacity(k);

    for blk in 0..n_tx_blocks {
        let mut tx_challenges: Vec<F128> = Vec::new();
        for (i, sub) in subs_padded.iter().enumerate() {
            let zero_data = vec![F128::ZERO; sub.layout.n_data];
            let d: &[F128] = if blk < k && i < n_real { &data[blk][i] } else { &zero_data };
            // Each sub-block is a STANDARD S-slot homogeneous block: slot 0 is
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
    DuplexUnion { committed, s0, s_out, fixed, refs, layout, w_log, block_log, challenges }
}

#[cfg(test)]
mod stage1_leaf_union_tests {
    use super::*;

    fn mixed_tiles(n: usize) -> Vec<LeafTile> {
        (0..n)
            .map(|i| {
                let i = i as u64;
                if i % 2 == 0 {
                    LeafTile::Source {
                        log_rows: 9,
                        leaf_index: (3 * i + 1) as usize,
                        syms: [F128 { lo: i + 1, hi: 2 }, F128 { lo: 3, hi: i + 4 }],
                    }
                } else {
                    LeafTile::HighPair {
                        layer_log: 12,
                        leaf_index: (2 * i + 1) as usize,
                        s0: F128 { lo: 5, hi: i + 6 },
                        s1: F128 { lo: i + 7, hi: 8 },
                    }
                }
            })
            .collect()
    }

    /// The shared leaf-union discharges mixed SB6 + SB8 tiles in ONE walk:
    /// native verify (inside `run_leaf_union_native`) + trace satisfiability +
    /// per-tile digest wires match the native digests. Confirms high-pair and
    /// source-leaf coexist as ONE family in a single periodic-pattern walk.
    #[test]
    fn leaf_union_mixed_native_and_trace() {
        let tiles = mixed_tiles(6);
        let u = build_leaf_union(&tiles);
        let native = run_leaf_union_native(&u, b"leaf-union-unit"); // native verifies internally

        let mut b = FieldR1csBuilder::new();
        for col in [
            &u.cols.in_[0],
            &u.cols.in_[1],
            &u.cols.c[0],
            &u.cols.c[1],
            &u.cols.c[2],
            &u.cols.c[3],
        ] {
            alloc_column_slice(&mut b, col, u.w_log);
        }
        let (claims, digest_wires) =
            discharge_leaf_union(&mut b, u.w_log, b"leaf-union-unit", &native, 0, &u.digests);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "leaf-union trace unsatisfiable");
        assert_eq!(digest_wires.len(), tiles.len(), "one digest wire per tile");
        for (t, dw) in digest_wires.iter().enumerate() {
            for lane in 0..2 {
                assert_eq!(dw[lane].eval(&z), u.digests[t][lane], "digest wire value");
            }
        }
        assert!(!claims.is_empty());
    }

    /// The multi-tile leaf union discharged through the REAL outer PCS: every
    /// tile's committed columns live as witness slices, the union's whole claim
    /// DAG is replayed in-trace, and `prove/verify_field_with_public_io` turns
    /// each pending terminal into an opening claim against the committed witness.
    /// A committed lane the prover flips afterward makes exactly one opening
    /// claim false — the BaseFold layer rejects it. This is the in-trace
    /// analogue of `region_merkle_slot_e2e` for the data-parallel leaf union:
    /// the discharge→PCS path the multi-tx wallet-PCS assembly rests on, proven
    /// end to end at multi-tile (multi-tx) scale.
    #[test]
    fn leaf_union_slot_end_to_end() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec};
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        const OUTER: &[u8] = b"leaf-union-slot-outer";
        let tiles = mixed_tiles(4); // 4 tiles = a multi-tx leaf union (2 source, 2 high-pair)
        let u = build_leaf_union(&tiles);
        let native = run_leaf_union_native(&u, b"leaf-union-slot");
        let w_log = u.w_log;

        let mut b = FieldR1csBuilder::new();
        let col_data: [&[F128]; 6] = [
            &u.cols.in_[0],
            &u.cols.in_[1],
            &u.cols.c[0],
            &u.cols.c[1],
            &u.cols.c[2],
            &u.cols.c[3],
        ];
        let slices: Vec<WitnessSlice> =
            col_data.iter().map(|c| alloc_column_slice(&mut b, c, w_log).0).collect();
        let (claims, _digest_wires) =
            discharge_leaf_union(&mut b, w_log, b"leaf-union-slot", &native, 0, &u.digests);

        // IO slice: (native_point ‖ native_value) per claim; the trace's replayed
        // (point, value) wires pin to it, and the spec derives one opening claim
        // per entry against the claim's committed column slice.
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
        assert!(r1cs.satisfies(&z), "honest leaf-union trace unsatisfiable");
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
            .expect("the leaf-union slot proof verifies");
        eprintln!(
            "[leaf-union-slot] tiles={}, rows={} (m={}), opening claims={}",
            tiles.len(),
            z.len(),
            r1cs.m,
            spec.claims.len()
        );

        // The money negative: flip ONE committed C0 lane. The trace stays
        // satisfiable (columns are free wires, bound only by opening claims) and
        // the envelope is unchanged, but the opening claim against the flipped
        // column is now FALSE — the PCS layer must reject.
        let mut bad_z = z.clone();
        let c0 = slices[2]; // C0
        bad_z[c0.start() + 5] += F128::ONE;
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
            "a flipped committed column lane must break its opening claim"
        );
    }

    /// Transaction-count independence: doubling the tile count raises the domain
    /// by one bit, so the ONE walk gains exactly one sumcheck round —
    /// logarithmic, not the K-fold of K separate per-tx walks.
    #[test]
    fn leaf_union_walk_is_flat() {
        let rounds = |n: usize| {
            run_leaf_union_native(&build_leaf_union(&mixed_tiles(n)), b"flat").walk_proof.layers[0]
                .round_coeffs
                .len()
        };
        let r2 = rounds(2);
        assert_eq!(rounds(4), r2 + 1, "K:2->4 adds one walk round");
        assert_eq!(rounds(8), r2 + 2, "K:2->8 adds two walk rounds");
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
                F128 { lo: r, hi: r.rotate_left(29) ^ 0xA5A5 }
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
        let data: Vec<Vec<F128>> =
            (0..2).map(|t| tx_data(&layout, 0xABCD_0000 + t as u64)).collect();
        let u = build_duplex_union(&layout, iv_flat(), &data);
        assert_ne!(u.challenges[0], u.challenges[1], "per-tx channels squeeze distinct challenges");
        let native = run_duplex_union_native(&u, b"duplex-union-unit");

        let mut b = FieldR1csBuilder::new();
        for col in u.committed.iter() {
            alloc_column_slice(&mut b, col, u.w_log);
        }
        let mut claims = discharge_duplex_union(&mut b, &u, b"duplex-union-unit", &native, 0);
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
        let data: Vec<Vec<F128>> =
            (0..k).map(|t| tx_data(&layout, 0xC0FE_0000 + t as u64)).collect();
        let u = build_duplex_union(&layout, iv_flat(), &data);
        let native = run_duplex_union_native(&u, b"duplex-union-slot");
        let w_log = u.w_log;

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> =
            u.committed.iter().map(|c| alloc_column_slice(&mut b, c, w_log).0).collect();
        let mut claims = discharge_duplex_union(&mut b, &u, b"duplex-union-slot", &native, 0);
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
        assert!(r1cs.satisfies(&z), "honest duplex-union trace unsatisfiable");
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
        let data: Vec<Vec<F128>> =
            (0..2).map(|t| tx_data(&layout, 0x5EED_0000 + t as u64)).collect();
        let u = build_duplex_union(&layout, iv_flat(), &data);
        let native = run_duplex_union_native(&u, b"duplex-raw-read");
        let w_log = u.w_log;

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> =
            u.committed.iter().map(|c| alloc_column_slice(&mut b, c, w_log).0).collect();
        // Discharge ONLY the walk (selection -> walk -> substitution -> shifts).
        // NO per-cell challenge reads: the Stage-2 pattern raw-reads instead.
        let claims = discharge_duplex_union(&mut b, &u, b"duplex-raw-read", &native, 0);

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
        assert_eq!(chal.eval(&z), u.challenges[0][0], "raw-read == native challenge");
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
        assert!(r1cs.satisfies(&bad_z), "the raw-read cell is unconstrained by the trace");
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (bad_proof, bad_commitment, _) =
            prove_field_with_public_io(&r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        assert!(
            verify_field_with_public_io(&r1cs, &bad_commitment, &bad_proof, &spec, &io_values, &mut ch_v)
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
            let data: Vec<Vec<F128>> =
                (0..k).map(|t| tx_data(&layout, 0xF1A7_0000 + t as u64)).collect();
            let u = build_duplex_union(&layout, iv_flat(), &data);
            run_duplex_union_native(&u, b"flat").walk_proof.layers[0].round_coeffs.len()
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
                F128 { lo: r, hi: r.rotate_left(29) ^ 0xA5A5 }
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
        assert_eq!((ch0.slots.len(), ch0.n_data, ch0.challenges.len()), (7, 6, 5));
        assert_eq!((ch1.slots.len(), ch1.n_data, ch1.challenges.len()), (4, 3, 3));
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        assert_ne!(iv0, iv1, "the two channels must carry different IVs");
        let subs = vec![
            SubChannel { layout: ch0.clone(), iv_flat: iv0 },
            SubChannel { layout: ch1.clone(), iv_flat: iv1 },
        ];
        let k = 2usize;
        let data: Vec<Vec<Vec<F128>>> = (0..k)
            .map(|t| vec![tx_data(&ch0, 0x1000 + t as u64), tx_data(&ch1, 0x2000 + t as u64)])
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
            assert_eq!(u.challenges[t].len(), n0 + n1, "concatenated challenge count");
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
        assert_ne!(u.challenges[0], u.challenges[1], "distinct tx data ⇒ distinct challenges");

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
            SubChannel { layout: ch0.clone(), iv_flat: iv0 },
            SubChannel { layout: ch1.clone(), iv_flat: iv1 },
            SubChannel { layout: ch2.clone(), iv_flat: iv2 },
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
        let (n0, n1, n2) = (ch0.challenges.len(), ch1.challenges.len(), ch2.challenges.len());
        assert_eq!(u.challenges.len(), k, "K real tx challenge streams (ghost tile excluded)");
        for t in 0..k {
            assert_eq!(u.challenges[t].len(), n0 + n1 + n2);
            assert_eq!(&u.challenges[t][0..n0], h0.challenges[t].as_slice());
            assert_eq!(&u.challenges[t][n0..n0 + n1], h1.challenges[t].as_slice());
            assert_eq!(&u.challenges[t][n0 + n1..n0 + n1 + n2], h2.challenges[t].as_slice());
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
            SubChannel { layout: ch0.clone(), iv_flat: iv0 },
            SubChannel { layout: ch1.clone(), iv_flat: iv1 },
        ];
        let data: Vec<Vec<Vec<F128>>> = (0..2)
            .map(|t| vec![tx_data(&ch0, 0x900 + t as u64), tx_data(&ch1, 0xA00 + t as u64)])
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
        assert_eq!(ones, vec![0, s], "START resets each sub-channel's carry at i·S");
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
        assert!(broke.is_err(), "removing the carry reset must break the heterogeneous discharge");
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
            SubChannel { layout: ch0.clone(), iv_flat: iv0 },
            SubChannel { layout: ch1.clone(), iv_flat: iv1 },
        ];
        let k = 2usize;
        let data: Vec<Vec<Vec<F128>>> = (0..k)
            .map(|t| vec![tx_data(&ch0, 0xC0FE_0000 + t as u64), tx_data(&ch1, 0xBEEF_0000 + t as u64)])
            .collect();
        let u = build_combined_duplex_union(&subs, &data);
        let native = run_duplex_union_native(&u, DOM);
        let w_log = u.w_log;

        // Build the trace: 6 committed columns as slices, ONE union discharge, and
        // each tx's challenges read from the carry cells.
        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> =
            u.committed.iter().map(|c| alloc_column_slice(&mut b, c, w_log).0).collect();
        let mut claims = discharge_duplex_union(&mut b, &u, DOM, &native, 0);
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
        assert!(r1cs.satisfies(&z), "honest combined-union trace unsatisfiable");
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
            assert!(r1cs.satisfies(&bad_z), "committed columns are free wires ({label})");
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
            SubChannel { layout: ch0.clone(), iv_flat: iv0 },
            SubChannel { layout: ch1.clone(), iv_flat: iv1 },
        ];

        // Walk rounds (layer 0 sumcheck rounds) grow by exactly one per K-doubling.
        let walk_rounds = |k: usize| {
            let data: Vec<Vec<Vec<F128>>> = (0..k)
                .map(|t| vec![tx_data(&ch0, 0xF00D + t as u64), tx_data(&ch1, 0xBA5E + t as u64)])
                .collect();
            let u = build_combined_duplex_union(&subs, &data);
            run_duplex_union_native(&u, b"combined-flat").walk_proof.layers[0].round_coeffs.len()
        };
        let r1 = walk_rounds(1);
        assert_eq!(walk_rounds(2), r1 + 1, "K:1->2 adds exactly one shared-walk round");
        assert_eq!(walk_rounds(4), r1 + 2, "K:1->4 adds exactly two shared-walk rounds");

        // Full-trace RAW wire counts (discharge + per-tx challenge reads), taken
        // BEFORE `build()` rounds up to a power of two — the padded `z.len()` would
        // hide the sub-linear growth (both K land in the same 2^m block).
        let trace_wires = |k: usize| -> usize {
            let data: Vec<Vec<Vec<F128>>> = (0..k)
                .map(|t| vec![tx_data(&ch0, 0xF00D + t as u64), tx_data(&ch1, 0xBA5E + t as u64)])
                .collect();
            let u = build_combined_duplex_union(&subs, &data);
            let native = run_duplex_union_native(&u, b"combined-flat");
            let mut b = FieldR1csBuilder::new();
            for c in u.committed.iter() {
                alloc_column_slice(&mut b, c, u.w_log);
            }
            let mut claims = discharge_duplex_union(&mut b, &u, b"combined-flat", &native, 0);
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
        assert!(w2 < 2 * w1, "K=2 must NOT be a second walk (sub-linear wire growth)");
        assert!(w2 - w1 < w1 / 2, "K-doubling grows the trace by ≪ a full walk");
    }
}

#[cfg(test)]
mod owner_auth_region_tests {
    use super::*;
    use noid_core::Block128;
    use noid_gkr::owner_auth::{
        compute_owner_auth_boundary, owner_auth_gkr_channel, prove_owner_auth_killshot,
        OwnerAuthCircuit, OwnerAuthInputs, OwnerAuthLayout,
    };
    use noid_ivc_core::challenger::FsLaneChallenger;
    use noid_ivc_core::pcs::{self, PcsParams};
    use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec};
    use noid_ivc_core::verifier::verify_field_with_public_io;
    use noid_ivc_prover::field_prover::prove_field_with_public_io;

    use crate::acceptance::trace::owner_auth::build_owner_auth_slot;

    /// Honest owner-auth fixture (mirrors `tests/owner_auth_channel_region.rs`):
    /// owners with secrets, addresses derived by the native boundary computation.
    /// Secrets run the native prover only; no secret-derived value enters a trace.
    fn fixture(owner_count: usize, seed: u128) -> (OwnerAuthProofKillShot, OwnerAuthPublicInputs) {
        let layout = OwnerAuthLayout::for_owner_count(owner_count).unwrap();
        let circuit = OwnerAuthCircuit::build(layout);
        let spend_secret: Vec<[Block128; 2]> = (0..owner_count)
            .map(|i| {
                [
                    Block128::from(seed + 1000 + i as u128),
                    Block128::from(seed + 2000 + i as u128),
                ]
            })
            .collect();
        let tx_body_hash = [Block128::from(seed + 7), Block128::from(seed + 8)];
        let expected_address =
            compute_owner_auth_boundary(&circuit, spend_secret.clone(), tx_body_hash);
        let live_input_positions: Vec<usize> = (0..owner_count).collect();
        let live_slot_indices: Vec<u32> = (0..owner_count as u32).map(|i| 100 + i).collect();
        let input_to_group: Vec<usize> = (0..owner_count).collect();
        let public = OwnerAuthPublicInputs::new(
            layout,
            tx_body_hash,
            live_input_positions,
            live_slot_indices,
            input_to_group,
            expected_address,
            owner_count.max(4),
        )
        .unwrap();
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
            let (p, pubx) = fixture(3, seed0 + (t as u128) * 0x1000);
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
        let input_ts: Vec<OwnerAuthPublicInputsTrace> =
            publics.iter().map(|pubx| OwnerAuthPublicInputsTrace::alloc(b, pubx)).collect();
        let (_obligations, claims) =
            discharge_owner_auth_killshots_via_region(b, &proof_ts, &input_ts, proofs, publics);
        assert!(!claims.is_empty(), "region discharge produced no opening claims");

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
        let (proof, public) = fixture(3, 0xA3);
        let mut b = FieldR1csBuilder::new();

        // Inline obligation (the canonical per-tx replay).
        let (_inputs_inline, obligation_inline) = build_owner_auth_slot(&mut b, &proof, &public);

        // Region obligation on freshly-allocated trace proof/inputs.
        let inputs_t = OwnerAuthPublicInputsTrace::alloc(&mut b, &public);
        let proof_t = OwnerAuthProofTrace::alloc(&mut b, &proof, public.layout);
        let (obligations_region, claims) = discharge_owner_auth_killshots_via_region(
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
        assert!(r1cs.satisfies(&z), "owner-auth region parity trace unsatisfiable");

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
            public.layout.num_vars,
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
        let (proof, public) = fixture(3, 0x0E2E);
        let mut b = FieldR1csBuilder::new();
        let (spec, io_values, claim_slices, _w_log) =
            region_slot_into_builder(&mut b, std::slice::from_ref(&proof), std::slice::from_ref(&public));
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest owner-auth region slot unsatisfiable");
        assert!(r1cs.m < 22, "gate guard: keep the region slot well under 2^22 rows");

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
            public.layout.num_vars,
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
            let streams: Vec<Vec<F128>> =
                pp.iter().zip(&uu).map(|(p, u)| owner_auth_channel_schedule(p, u).data_flat).collect();
            let u_c = build_duplex_union(&chan_layout, iv, &streams);
            run_duplex_union_native(&u_c, OWNER_AUTH_DOMAIN_C).walk_proof.layers[0]
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
