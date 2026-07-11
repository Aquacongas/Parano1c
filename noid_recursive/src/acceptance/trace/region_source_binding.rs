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
//! ## Structure — three core walks + compact metadata walks + one transcript host
//! A single deep-chain walk is ~1M rows; one walk per family OOMs (region
//! prover memory note). The assembly uses these union walks:
//!   - **wallet walk A (leaf-union)**: the source + mid capsule-leaf tiles on
//!     six IN/C columns and their natural K-wide domain.
//!   - **block-meta walk A (optional)**: exact-state sponge tiles + spine
//!     tree/wrap, packed into two aligned dyadic regions on eight columns.
//!   - **wallet walk B (merkle-union)**: only the two feed-forward capsule
//!     legs, on their natural K-wide domain.
//!   - **block-meta walk B (optional)**: the legacy exact-state / tx-root
//!     2-permutation legs, on a separate compact domain.  Keeping these legs
//!     off wallet B avoids rounding the sum of two unrelated per-block
//!     geometries to the next dyadic domain.
//!   - **walk C (duplex-union)**: the K txs' FRICHANL channels.
//!   - **walk D (recording-only duplex)**: hosts walk C's discharge transcript
//!     once. D's own discharge is the single inline replay; there is no second
//!     hosting level.
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
//! The recomputed ff root is copied by the existing CR-chain equation into
//! the first spare stride-tail cell, then that committed CR cell is pinned
//! directly to the observed wire. Query POSITIONS are bound exactly without
//! duplicate bit witnesses: the packed seed recomposition consumes the live
//! and spare-tail D cells directly. The D committed slice itself is allocated
//! with exact boolean R1CS rows (not a pre-commit random-point relation), and
//! one exact equality joins the duplicated source/mid low bit. Each leaf
//! tile's meta cell remains bound to its bit-recomposed leaf index.
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
    absorb_capsule_commitment, capsule_leaf_hash, capsule_leaf_of_position,
    capsule_queries_from_seeds, capsule_query_seed_count, capsule_tree_depth, CapsuleNodeHasher,
    CAPSULE_CAP_DEPTH, CAPSULE_GRIND_BITS, CAPSULE_LEAF_SYMBOLS, CAPSULE_LOG_RATE,
    CAPSULE_NUM_QUERIES, CAPSULE_RATE, CAPSULE_TAU, CAPSULE_WIDE_LOG,
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
    ColumnRelationProof, FixedPattern, RelationColumns, RelationError, RelationTerm,
    ShiftDischargeProof,
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
    build_spine_instance_columns, spine_tree_exposure_terms, spine_tree_fixed_patterns,
    spine_tree_internal_child_pattern, spine_wrap_fixed_patterns, SpineInstanceFlat,
    SPINE_TREE_KID_LEAF_BASE, SPINE_TREE_LEAVES, SPINE_TREE_SLOTS, SPINE_WRAP_SLOT,
    SPINE_WRAP_SLOTS,
};
use noid_ivc_core::deep_chain::{
    prove_deep_chain_walk, verify_deep_chain_walk, DeepChainWalkProof, LaneClaimGroup, WalkError,
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
use super::exact_state::{ExactStatePairedRegionData, ExactStateRegionData};
#[cfg(test)]
use super::fri_pcs::forward_ntt_trace;
use super::fri_pcs::{
    compact_queries_from_squeezes_with_bits, mle_evaluate_small_trace,
    packed_capsule_queries_from_seeds_with_bound_bits,
};
use super::owner_auth::{
    owner_boundary_constraints, owner_boundary_target, owner_boundary_w,
    owner_combined_target_trace, owner_shift_weights_at_point, owner_unified_final_evals,
    OwnerAuthProofTrace, OwnerAuthPublicInputsTrace, OwnerUnifiedReductionTrace,
    PendingAuthPcsObligation,
};
use super::paired_merkle_update::{
    build_paired_merkle_update_columns, paired_merkle_update_fixed_patterns,
    paired_merkle_update_refs, paired_merkle_update_substitution_terms, paired_update_root_offsets,
    PairedMerkleUpdateRefs, PAIRED_UPDATE_DEPTH, PAIRED_UPDATE_SLOTS_PER_LEVEL,
    PAIRED_UPDATE_STRIDE,
};
use super::{alloc_blocks, eq_ind_trace, flat_of, mul, pin_eq, pin_zero, BatchEvalReductionTrace};
use crate::acceptance::region::{
    capsule_pcs_channel_schedule, owner_auth_channel_schedule, CAPSULE_OPEN_TAG,
};

// FS domains for the region walks (self-contained sub-protocols; the soundness
// of the discharge lives in the committed-column opening claims the caller
// threads through the outer PCS, not in these transcripts).  Wallet capsule
// leaves and block metadata intentionally use independent transcripts: their
// very different natural domains must never force one another to round up.
const DOMAIN_A_WALLET: &[u8] = b"source-binding-wallet-leaf-union";
const DOMAIN_A_META: &[u8] = b"source-binding-block-meta-union";
const DOMAIN_B_WALLET: &[u8] = b"source-binding-wallet-merkle-union";
const DOMAIN_B_META: &[u8] = b"source-binding-block-meta-merkle-union";
const DOMAIN_C: &[u8] = b"source-binding-full-duplex-union";
const DOMAIN_D: &[u8] = b"source-binding-recording-only-host";

// Wallet walk-A committed order.  Capsule leaves only need their two absorb
// lanes and four carry/output lanes; KID/CODE belong exclusively to block
// metadata and must not inflate this K-wide domain.
const WALLET_IN0: usize = 0;
const WALLET_C0: usize = 2;
const N_WALLET_COMMITTED: usize = 6;

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
const N_META_COMMITTED: usize = 8;

/// One block-tiled walk domain. `bases[i]` is the start of leg `i` inside a
/// block; the block and full walk are independently rounded to powers of two.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TiledWalkLayout {
    bases: Vec<usize>,
    live_per_block: usize,
    block_log: usize,
    block_slots: usize,
    w_log: usize,
    slots: usize,
}

/// Lay out non-empty, disjoint leg slot ranges in one K-tiled walk.
fn tiled_walk_layout(k: usize, leg_slots: &[usize]) -> TiledWalkLayout {
    assert!(k.is_power_of_two(), "walk tile count must be dyadic");
    assert!(!leg_slots.is_empty(), "walk needs at least one leg");
    assert!(leg_slots.iter().all(|&n| n > 0), "empty walk leg");
    let mut bases = Vec::with_capacity(leg_slots.len());
    let mut live_per_block = 0usize;
    for &slots in leg_slots {
        bases.push(live_per_block);
        live_per_block = live_per_block
            .checked_add(slots)
            .expect("walk block geometry overflow");
    }
    let block_slots = live_per_block.next_power_of_two();
    let block_log = block_slots.trailing_zeros() as usize;
    let slots = k
        .checked_mul(block_slots)
        .expect("walk domain geometry overflow");
    debug_assert!(slots.is_power_of_two());
    TiledWalkLayout {
        bases,
        live_per_block,
        block_log,
        block_slots,
        w_log: slots.trailing_zeros() as usize,
        slots,
    }
}

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

/// Fixed-capacity cells exposed by one local depth-16 paired update.
#[derive(Clone)]
pub struct PairedLocalExactStateCells {
    pub old_entry: [LinExpr; 2],
    pub new_entry: [LinExpr; 2],
    pub old_root: [LinExpr; 2],
    pub new_root: [LinExpr; 2],
    /// One old-even direction cell per level. The paired new-even copy is
    /// tied to it by exact Stage-2 equality constraints.
    pub directions: [LinExpr; PAIRED_UPDATE_DEPTH],
}

/// Fixed-capacity cells exposed by one upper paired update. All sixteen root
/// depths are carried; the later consumer, not this region, selects the
/// header-bound active upper depth.
#[derive(Clone)]
pub struct PairedUpperExactStateCells {
    pub old_entry: [LinExpr; 2],
    pub new_entry: [LinExpr; 2],
    pub old_roots: [[LinExpr; 2]; PAIRED_UPDATE_DEPTH],
    pub new_roots: [[LinExpr; 2]; PAIRED_UPDATE_DEPTH],
    pub directions: [LinExpr; PAIRED_UPDATE_DEPTH],
}

/// Block-slots handoff for the paired exact-state carrier. Vector lengths are
/// the class capacities, not the live update counts.
#[derive(Clone)]
pub struct PairedExactStateCells {
    pub local: Vec<PairedLocalExactStateCells>,
    pub upper: Vec<PairedUpperExactStateCells>,
}

/// Extended plural discharge result. The legacy API returns only `claims`;
/// block-slots can opt into this result when it is ready to consume the paired
/// entry/root/direction cells.
pub struct AuthPcsRegionDischarge {
    pub claims: Vec<RegionPcsClaim>,
    pub paired: Option<PairedExactStateCells>,
}

const AUTH_PCS_REGION_SIDECAR_PURPOSE_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/AUTH-PCS-PRODUCTION/V1";

fn auth_pcs_region_sidecar_purpose(role: &[u8], walk_domain: &[u8]) -> [u8; 32] {
    noid_poseidon2b::native::poseidon2b_hash_byte_slices(
        AUTH_PCS_REGION_SIDECAR_PURPOSE_DOMAIN,
        &[role, walk_domain],
    )
}

/// Canonical role purpose for the wallet capsule-leaf Walk-A vertical.
pub fn auth_pcs_wallet_a_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"wallet-a", DOMAIN_A_WALLET)
}

/// Canonical role purpose for the exact-state/body-spine Walk-A vertical.
pub fn auth_pcs_meta_a_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"meta-a", DOMAIN_A_META)
}

/// Canonical role purpose for the wallet capsule-path Walk-B vertical.
pub fn auth_pcs_wallet_b_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"wallet-b", DOMAIN_B_WALLET)
}

/// Canonical role purpose for the exact-state/tx-root Walk-B vertical.
pub fn auth_pcs_meta_b_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"meta-b", DOMAIN_B_META)
}

/// Canonical role purpose for the recording-free main FRICHANL Walk-C.
pub fn auth_pcs_main_c_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"main-c", DOMAIN_C)
}

/// Owning recording-free handoff for the five mandatory wallet/meta region
/// verticals.  Every committed slice is already present in the enclosing
/// Field witness and all statement/cell equalities are already in its R1CS.
/// The endpoints are native prover input and may only be consumed after that
/// witness has been committed.
pub struct AuthPcsRegionPreparation {
    pub wallet_a_vk: crate::region_sidecar::WalkARegionVk,
    pub wallet_a_endpoints: crate::region_sidecar::RegionWalkEndpoints,
    pub meta_a_vk: crate::region_sidecar::WalkARegionVk,
    pub meta_a_endpoints: crate::region_sidecar::RegionWalkEndpoints,
    pub wallet_b_vk: crate::region_sidecar::MerkleRegionVk,
    pub wallet_b_endpoints: crate::region_sidecar::RegionWalkEndpoints,
    pub meta_b_vk: crate::region_sidecar::MerkleRegionVk,
    pub meta_b_endpoints: crate::region_sidecar::RegionWalkEndpoints,
    pub main_c_vk: crate::region_sidecar::DuplexRegionVk,
    pub main_c_endpoints: crate::region_sidecar::RegionWalkEndpoints,
    pub paired: PairedExactStateCells,
}

impl AuthPcsRegionPreparation {
    pub fn wallet_a_prover_plan(
        &self,
    ) -> Result<
        crate::region_sidecar::WalkARegionProverPlan<'_>,
        crate::region_sidecar::RegionSidecarError,
    > {
        crate::region_sidecar::WalkARegionProverPlan::new(
            &self.wallet_a_vk,
            self.wallet_a_endpoints.s0(),
            self.wallet_a_endpoints.s_out(),
        )
    }

    pub fn meta_a_prover_plan(
        &self,
    ) -> Result<
        crate::region_sidecar::WalkARegionProverPlan<'_>,
        crate::region_sidecar::RegionSidecarError,
    > {
        crate::region_sidecar::WalkARegionProverPlan::new(
            &self.meta_a_vk,
            self.meta_a_endpoints.s0(),
            self.meta_a_endpoints.s_out(),
        )
    }

    pub fn wallet_b_prover_plan(
        &self,
    ) -> Result<
        crate::region_sidecar::MerkleRegionProverPlan<'_>,
        crate::region_sidecar::RegionSidecarError,
    > {
        crate::region_sidecar::MerkleRegionProverPlan::new(
            &self.wallet_b_vk,
            self.wallet_b_endpoints.s0(),
            self.wallet_b_endpoints.s_out(),
        )
    }

    pub fn meta_b_prover_plan(
        &self,
    ) -> Result<
        crate::region_sidecar::MerkleRegionProverPlan<'_>,
        crate::region_sidecar::RegionSidecarError,
    > {
        crate::region_sidecar::MerkleRegionProverPlan::new(
            &self.meta_b_vk,
            self.meta_b_endpoints.s0(),
            self.meta_b_endpoints.s_out(),
        )
    }

    pub fn main_c_prover_plan(
        &self,
    ) -> Result<
        crate::region_sidecar::DuplexRegionProverPlan<'_>,
        crate::region_sidecar::RegionSidecarError,
    > {
        crate::region_sidecar::DuplexRegionProverPlan::new(
            &self.main_c_vk,
            self.main_c_endpoints.s0(),
            self.main_c_endpoints.s_out(),
        )
    }
}

enum AuthPcsRegionMode<'a> {
    Prepare,
    LegacyDischarge {
        oa_recording: Option<&'a RecordedChannel>,
    },
}

enum AuthPcsRegionAssemblyResult {
    Preparation(AuthPcsRegionPreparation),
    LegacyDischarge(AuthPcsRegionDischarge),
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
/// link's public IO. The K txs' capsule leaves tile a six-column wallet walk A;
/// block-level leaf/spine families occupy a separate compact block-meta walk A;
/// capsule Merkle legs tile wallet-B while legacy state/tx-root legs tile the
/// independent compact meta-B.
///
/// `es` (exact-state region handoff, [`ExactStateRegionData`]): when `Some`,
/// the `2T` slot-leaf sponge tiles occupy the minimal dyadic EXSTSLT region of
/// block-meta A (canonical sponge ghosts fill its tail); the state paths
/// (TAG_EXSTNOD) join walk B as one more Merkle leg, chunked `ceil(len/K)` per
/// tx block. Leaf digests pin to the slot-leaf `expected_leaf` statement
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
/// every transaction's final 31-permutation body hash rides block-meta A as
/// TWO families — the 32-slot compress TREE (30 active COMPRESS permutations,
/// zero `LEAFODD`) and a separate one-slot `TAG_TX8X2` WRAP. Joins are cell
/// pins: all sixteen raw statement leaves → tree KID leaf cells, the tree root
/// → the wrap `IN` cells, and the wrap digest → the `tx_hashes` statement
/// wires (which the tx-root leg and owner-auth statements already consume).
/// Instances are chunked `ceil(n/K)` per tx block with canonical zero-leaf
/// GHOST spines past the real count.
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
    legacy_region_claims(
        discharge_auth_pcs_obligations_via_region_with_paired_handoff(
            b,
            obligations,
            natives,
            params,
            es,
            txr,
            spine,
            oa_recording,
        ),
    )
}

#[inline]
fn legacy_region_claims(output: AuthPcsRegionDischarge) -> Vec<RegionPcsClaim> {
    output.claims
}

/// Recording-free production preparation for the five wallet/meta region
/// verticals.  This retains the complete symbolic transcript/query algebra
/// and exact Stage-2 cell pins, but deliberately stops before every legacy
/// native/deep-chain discharge, transcript recorder, RegionPcsClaim tail, and
/// recording-only D host.
///
/// Production is represented as a total type: meta-A, meta-B, and the paired
/// exact-state handoff are mandatory.  Transitional legacy exact-state paths
/// remain accepted only by the old discharge API below.
pub fn prepare_auth_pcs_obligations_via_region_with_paired_handoff(
    b: &mut FieldR1csBuilder,
    obligations: &[PendingAuthPcsObligation],
    natives: &[AuthMleOpeningProof],
    params: RegionDischargeParams,
    es: &ExactStateRegionData,
    txr: &TxRootRegionData,
    spine: &SpineRegionData,
) -> AuthPcsRegionPreparation {
    match auth_pcs_obligations_via_region_impl(
        b,
        obligations,
        natives,
        params,
        Some(es),
        Some(txr),
        Some(spine),
        AuthPcsRegionMode::Prepare,
    ) {
        AuthPcsRegionAssemblyResult::Preparation(preparation) => preparation,
        AuthPcsRegionAssemblyResult::LegacyDischarge(_) => unreachable!(),
    }
}

/// Extended plural discharge retaining the paired exact-state committed-cell
/// handoff. It is intentionally separate from the stable Vec-return API so
/// block-slots can migrate without changing existing callers or claim order.
pub fn discharge_auth_pcs_obligations_via_region_with_paired_handoff(
    b: &mut FieldR1csBuilder,
    obligations: &[PendingAuthPcsObligation],
    natives: &[AuthMleOpeningProof],
    params: RegionDischargeParams,
    es: Option<&ExactStateRegionData>,
    txr: Option<&TxRootRegionData>,
    spine: Option<&SpineRegionData>,
    oa_recording: Option<&RecordedChannel>,
) -> AuthPcsRegionDischarge {
    match auth_pcs_obligations_via_region_impl(
        b,
        obligations,
        natives,
        params,
        es,
        txr,
        spine,
        AuthPcsRegionMode::LegacyDischarge { oa_recording },
    ) {
        AuthPcsRegionAssemblyResult::LegacyDischarge(discharge) => discharge,
        AuthPcsRegionAssemblyResult::Preparation(_) => unreachable!(),
    }
}

#[allow(clippy::too_many_arguments)]
fn auth_pcs_obligations_via_region_impl(
    b: &mut FieldR1csBuilder,
    obligations: &[PendingAuthPcsObligation],
    natives: &[AuthMleOpeningProof],
    params: RegionDischargeParams,
    es: Option<&ExactStateRegionData>,
    txr: Option<&TxRootRegionData>,
    spine: Option<&SpineRegionData>,
    mode: AuthPcsRegionMode<'_>,
) -> AuthPcsRegionAssemblyResult {
    let preparing = matches!(&mode, AuthPcsRegionMode::Prepare);
    let oa_recording = match mode {
        AuthPcsRegionMode::Prepare => None,
        AuthPcsRegionMode::LegacyDischarge { oa_recording } => oa_recording,
    };
    // Transitional claims remain scoped to this shared implementation until
    // the recording-free finalizer returns above the legacy discharge tail.
    let mut claims: Vec<Claim> = Vec::new();
    assert_eq!(
        obligations.len(),
        natives.len(),
        "one native proof per obligation"
    );
    assert!(!obligations.is_empty(), "at least one obligation");
    // The K txs tile wallet-A, wallet-B and walk-C at common-period offsets;
    // block metadata uses compact optional A/B walks when present.
    let k = obligations.len();
    assert!(
        k.is_power_of_two(),
        "wallet-PCS region discharge expects a power-of-two obligation count \
         (pad the tier's real txs with ghost obligations); got {k}"
    );
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

    // Wallet walk A is exactly `[tx_hi | two capsule-leaf families]`.  At the
    // production nq=64 this is 2*64*16 = 2048 slots/tx, hence P=K*2048.  Its
    // six committed columns are independent of every block-level family.
    let wallet_per_tx = n_leaf_families * leaf_family_slots;
    assert!(wallet_per_tx.is_power_of_two(), "wallet A block is dyadic");
    let wallet_block_log = wallet_per_tx.trailing_zeros() as usize;
    let wallet_p = k * wallet_per_tx;
    let wallet_w_log = wallet_p.trailing_zeros() as usize;
    let leaf_base = |f: usize| f * leaf_family_slots; // within a wallet tx block

    // Block-meta walk A packs EXSTSLT and the body spine into separate aligned
    // dyadic regions.  EXSTSLT uses the minimal power of two covering all 2T
    // sponge slots.  Spine keeps trees first and wraps second within a compact
    // per-tx block; one spare dyadic half makes exposure re-pointing constant.
    let es_region_slots = es.map_or(0, |e| {
        assert!(!e.leaves.is_empty(), "exact-state handoff without leaves");
        (e.leaves.len() * SPONGE_LEAF_SLOTS).next_power_of_two()
    });
    let spine_cap = spine.map_or(0, |s| {
        assert!(!s.instances.is_empty(), "spine handoff without instances");
        s.instances.len().div_ceil(k)
    });
    assert!(
        spine_cap == 0 || spine_cap.is_power_of_two(),
        "spine per-block capacity must be a power of two (got {spine_cap})"
    );
    let spine_tree_base = 0usize;
    let spine_wrap_base = spine_cap * SPINE_TREE_SLOTS;
    let spine_per_tx = if spine_cap > 0 {
        (spine_cap * (SPINE_TREE_SLOTS + SPINE_WRAP_SLOTS)).next_power_of_two()
    } else {
        0
    };
    let spine_block_log = spine_per_tx.trailing_zeros() as usize;
    let spine_region_slots = k * spine_per_tx;
    let has_meta = es.is_some() || spine.is_some();
    let has_both_meta_families = es.is_some() && spine.is_some();
    let meta_half = es_region_slots.max(spine_region_slots);
    let meta_p = if has_both_meta_families {
        2 * meta_half
    } else {
        meta_half.max(1)
    };
    let meta_w_log = meta_p.trailing_zeros() as usize;
    let es_meta_base = 0usize;
    let spine_meta_base = if has_both_meta_families { meta_half } else { 0 };

    // Split walk-B leg layouts (class constant). The two wallet legs are
    // FEED-FORWARD (1 slot per node, stride = depth.next_pow2): the source
    // paths run to the committed cap (depth = tree − cap), the mid paths to
    // the root. The exact-state / tx-root legs stay on the 2-permutation
    // family (consensus trees are unchanged) in optional meta-B; their node
    // capacity IV remains a per-leg pattern parameter.
    let ff_depths: [usize; 2] = [
        capsule_tree_depth(num_vars) - CAPSULE_CAP_DEPTH,
        capsule_tree_depth(mid_log),
    ];
    let depth_s = ff_depths[0];
    let depth_m = ff_depths[1];
    let ff_strides: [usize; 2] = std::array::from_fn(|f| ff_depths[f].next_power_of_two());
    let paired_es: Option<&ExactStatePairedRegionData> = es.and_then(|e| e.paired.as_ref());
    let mut leg_depths: Vec<usize> = Vec::new();
    let mut leg_caps: Vec<usize> = Vec::new();
    let mut leg_ivs: Vec<[F128; 2]> = Vec::new();
    let mut es_state_leg: Option<usize> = None;
    if let Some(e) = es {
        if e.paired.is_some() {
            assert!(
                e.paths.is_empty(),
                "paired exact-state handoff must not retain legacy paths"
            );
        } else {
            assert!(
                !e.paths.is_empty(),
                "legacy exact-state path handoff is empty"
            );
            es_state_leg = Some(leg_depths.len());
            leg_depths.push(e.d_state);
            leg_caps.push(e.paths.len().div_ceil(k));
            leg_ivs.push(iv_flat_of_tag(TAG_EXSTNOD));
        }
    }
    // Tx-root paths: one TAG_COMPRESS leg, one path per user tx chunked
    // across the tx blocks.
    let mut txr_leg: Option<usize> = None;
    if let Some(t) = txr {
        assert!(!t.paths.is_empty(), "tx-root region handoff without paths");
        txr_leg = Some(leg_depths.len());
        leg_depths.push(t.depth);
        leg_caps.push(t.paths.len().div_ceil(k));
        leg_ivs.push(compress_iv_flat());
    }
    let n_legs = leg_depths.len();
    // Split walk B at the semantic boundary. Wallet-B contains exactly the
    // two feed-forward capsule legs; optional meta-B contains only the legacy
    // exact-state / tx-root legs. Each side rounds its own per-tx geometry,
    // which is the measured B255 saving over rounding their sum.
    let wallet_leg_slots: [usize; 2] = std::array::from_fn(|f| nq * ff_strides[f]);
    let wallet_b = tiled_walk_layout(k, &wallet_leg_slots);
    let ff_bases: [usize; 2] = wallet_b
        .bases
        .as_slice()
        .try_into()
        .expect("exactly two wallet-B legs");
    let paired_caps_per_block: Option<[usize; 2]> = paired_es.map(|paired| {
        assert!(
            paired.touched_capacity > 0,
            "paired local capacity is empty"
        );
        assert!(
            paired.segment_capacity > 0,
            "paired upper capacity is empty"
        );
        [
            paired.touched_capacity.div_ceil(k),
            paired.segment_capacity.div_ceil(k),
        ]
    });
    let mut meta_slot_families: Vec<usize> = paired_caps_per_block
        .map(|caps| caps.map(|cap| cap * PAIRED_UPDATE_STRIDE).to_vec())
        .unwrap_or_default();
    let paired_family_count = meta_slot_families.len();
    let meta_leg_slots: Vec<usize> = (0..n_legs)
        .map(|f| leg_caps[f] * (2 * leg_depths[f]).next_power_of_two())
        .collect();
    meta_slot_families.extend(meta_leg_slots);
    let meta_b =
        (!meta_slot_families.is_empty()).then(|| tiled_walk_layout(k, &meta_slot_families));
    let paired_bases: Option<[usize; 2]> = paired_caps_per_block.map(|_| {
        meta_b.as_ref().expect("paired carrier needs meta-B").bases[..paired_family_count]
            .try_into()
            .expect("local and upper paired bases")
    });
    let meta_bases: Vec<usize> = meta_b.as_ref().map_or_else(Vec::new, |layout| {
        layout.bases[paired_family_count..].to_vec()
    });

    // Each walk-B committed set is leg-count FLAT: its legs' slot ranges are
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
    // Wallet/meta columns, each ghost-filled once with perm([0;4]).  The
    // wallet set is deliberately only IN(2)+C(4); block metadata retains the
    // full KID/IN/C set on its much smaller domain.
    // ===================================================================
    let mut wallet_cols: Vec<Vec<F128>> = (0..N_WALLET_COMMITTED)
        .map(|_| vec![F128::ZERO; wallet_p])
        .collect();
    let mut wallet_s0: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; wallet_p]);
    let mut wallet_s_out: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; wallet_p]);
    let mut meta_cols: Vec<Vec<F128>> = (0..N_META_COMMITTED)
        .map(|_| vec![F128::ZERO; meta_p])
        .collect();
    let mut meta_s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; meta_p]);
    let mut meta_s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; meta_p]);
    let (ghost_s0, ghost_out) =
        noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..wallet_p {
        for j in 0..STATE_SIZE {
            wallet_s0[j][slot] = ghost_s0[j];
            wallet_s_out[j][slot] = ghost_out[j];
            wallet_cols[WALLET_C0 + j][slot] = ghost_out[j];
        }
    }
    for slot in 0..meta_p {
        for j in 0..STATE_SIZE {
            meta_s0[j][slot] = ghost_s0[j];
            meta_s_out[j][slot] = ghost_out[j];
            meta_cols[C0 + j][slot] = ghost_out[j];
        }
    }
    let mut cb_wallet_b: Vec<Vec<F128>> = (0..n_committed_b)
        .map(|_| vec![F128::ZERO; wallet_b.slots])
        .collect();
    let mut s0_wallet_b: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; wallet_b.slots]);
    let mut sout_wallet_b: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; wallet_b.slots]);
    let meta_b_slots = meta_b.as_ref().map_or(0, |layout| layout.slots);
    let mut cb_meta_b: Vec<Vec<F128>> = (0..n_committed_b)
        .map(|_| vec![F128::ZERO; meta_b_slots])
        .collect();
    let mut s0_meta_b: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; meta_b_slots]);
    let mut sout_meta_b: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; meta_b_slots]);
    let (ghb0, ghbo) = noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..wallet_b.slots {
        for j in 0..STATE_SIZE {
            s0_wallet_b[j][slot] = ghb0[j];
            sout_wallet_b[j][slot] = ghbo[j];
            cb_wallet_b[j][slot] = ghbo[j];
        }
    }
    for slot in 0..meta_b_slots {
        for j in 0..STATE_SIZE {
            s0_meta_b[j][slot] = ghb0[j];
            sout_meta_b[j][slot] = ghbo[j];
            cb_meta_b[j][slot] = ghbo[j];
        }
    }

    // ===================================================================
    // Accumulators filled by the per-tx loop, assembled after it.
    // ===================================================================
    // Stage 2: per-cell reads/pins (grand pins, symbols, digests, fold-join) are
    // R1CS constraints, NOT IO opening claims -- the columns are opened by the
    // post-commit sidecars (or the transitional walk discharges), so every cell
    // is bound. Collected as (col, slot, wire) and resolved post-loop as
    // pin_eq(wire, cell). Wallet-A, meta-A and walk-B use explicit slices below.
    let mut cell_pins_wallet: Vec<(usize, usize, LinExpr)> = Vec::new();
    let mut cell_pins_meta: Vec<(usize, usize, LinExpr)> = Vec::new();
    let mut cell_pins_wallet_b: Vec<(usize, usize, LinExpr)> = Vec::new();
    let mut cell_pins_meta_b: Vec<(usize, usize, LinExpr)> = Vec::new();
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
    // Feed-forward wallet legs: entry pins go through `cell_pins_wallet_b`.
    // The existing CR chain exposes each final digest in the first spare
    // stride-tail CR cell, so roots need only one direct equality per lane.
    let mut ff_root_copy_pins: Vec<(usize, [LinExpr; 2])> = Vec::new();
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
        let tx_off_wallet = tx * wallet_per_tx;
        let tx_off_wallet_b = tx * wallet_b.block_slots;
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
        // Native channel data is assembled before any per-tx symbolic
        // algebra. Its challenge cells remain witness wires in phase 2.
        let schedule = capsule_pcs_channel_schedule(native, num_vars, &point);
        chan_data_streams.push(schedule.data_flat.clone());
        let native_queries = derive_queries(native, &point);

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
            let base = tx_off_wallet + leaf_base(fam);
            let n_copy = nq * leaf_stride;
            for j in 0..2 {
                wallet_cols[WALLET_IN0 + j][base..base + n_copy]
                    .copy_from_slice(&tc.in_[j][..n_copy]);
            }
            for j in 0..STATE_SIZE {
                wallet_cols[WALLET_C0 + j][base..base + n_copy].copy_from_slice(&tc.c[j][..n_copy]);
                wallet_s0[j][base..base + n_copy].copy_from_slice(&tc.s0[j][..n_copy]);
                wallet_s_out[j][base..base + n_copy].copy_from_slice(&tc.s_out[j][..n_copy]);
            }
            fam_digest_vals[fam] = digests;
        }

        // Native feed-forward path columns. Their symbolic direction/root
        // bindings are added only after wallet-A and walk-B slices exist.
        let src_witnesses: Vec<FfMerklePathWitness> = (0..nq)
            .map(|q| {
                let path = src_paths
                    .iter()
                    .find(|pth| pth.leaf_index == source_leaves_idx[q])
                    .expect("source path");
                assert_eq!(
                    lanes_raw(&path.leaf_hash),
                    fam_digest_vals[0][q],
                    "source tile digest != native leaf"
                );
                FfMerklePathWitness {
                    entry: fam_digest_vals[0][q],
                    siblings: path.siblings.iter().map(lanes_raw).collect(),
                    directions: (0..depth_s)
                        .map(|kk| (source_leaves_idx[q] >> kk) & 1 == 1)
                        .collect(),
                }
            })
            .collect();
        let mid_witnesses: Vec<FfMerklePathWitness> = (0..nq)
            .map(|q| {
                let path = mid_paths
                    .iter()
                    .find(|pth| pth.leaf_index == mid_leaves_idx[q])
                    .expect("mid path");
                assert_eq!(
                    lanes_raw(&path.leaf_hash),
                    fam_digest_vals[1][q],
                    "mid tile digest != native leaf"
                );
                FfMerklePathWitness {
                    entry: fam_digest_vals[1][q],
                    siblings: path.siblings.iter().map(lanes_raw).collect(),
                    directions: (0..depth_m)
                        .map(|kk| (mid_leaves_idx[q] >> kk) & 1 == 1)
                        .collect(),
                }
            })
            .collect();

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
                &mut cb_wallet_b,
                &mut s0_wallet_b,
                &mut sout_wallet_b,
                &fcols,
                tx_off_wallet_b + ff_bases[fam],
                nq * ff_strides[fam],
            );
            for q in 0..nq {
                let committed = if fam == 0 {
                    lanes_raw(&native.commitment.cap.hashes[source_leaves_idx[q] >> depth_s])
                } else {
                    lanes_raw(&opening.mid_root)
                };
                assert_eq!(fcols.roots[q], committed, "ff leg root != committed root");
                let root_copy = family
                    .root_copy_offset()
                    .expect("wallet ff depth must leave one stride-tail slot");
                assert_eq!(
                    [
                        fcols.cr[0][q * ff_strides[fam] + root_copy],
                        fcols.cr[1][q * ff_strides[fam] + root_copy],
                    ],
                    committed,
                    "ff root-copy cell != committed root"
                );
            }
        }
        fill_wallet_query_bit_carriers(
            &mut cb_wallet_b[8],
            tx_off_wallet_b,
            ff_bases,
            ff_strides,
            ff_depths,
            &native_queries,
            nq,
            num_vars,
        );
    } // end native column assembly over txs

    // ===================================================================
    // Paired exact-state families (optional): fixed-capacity local and upper
    // updates are independently chunked over the K meta-B blocks. Every
    // update occupies exactly 64 slots; overhang in the final K tile is the
    // paired builder's canonical ghost. Stage 2 pins every such committed
    // cell to that canonical value and the handoff does not expose it.
    // ===================================================================
    if let Some(paired) = paired_es {
        let packed = paired.packed_updates();
        assert_eq!(
            packed.updates.len(),
            paired.touched_capacity + paired.segment_capacity,
            "paired packed capacity"
        );
        assert_eq!(
            packed.active_slots,
            packed.updates.len() * PAIRED_UPDATE_STRIDE,
            "paired packed active slots"
        );
        let (local_updates, upper_updates) = packed.updates.split_at(paired.touched_capacity);
        let partitions = [local_updates, upper_updates];
        let caps = paired_caps_per_block.expect("paired per-block capacities");
        let bases = paired_bases.expect("paired meta-B bases");
        let layout = meta_b.as_ref().expect("paired carrier needs meta-B");
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        for blk in 0..k {
            for family in 0..2 {
                let cap = caps[family];
                let lo = (blk * cap).min(partitions[family].len());
                let hi = ((blk + 1) * cap).min(partitions[family].len());
                let family_slots = cap * PAIRED_UPDATE_STRIDE;
                let family_w_log = family_slots.next_power_of_two().trailing_zeros() as usize;
                let columns = build_paired_merkle_update_columns(
                    &partitions[family][lo..hi],
                    iv,
                    family_w_log,
                );
                place_paired_merkle_updates(
                    &mut cb_meta_b,
                    &mut s0_meta_b,
                    &mut sout_meta_b,
                    &columns,
                    blk * layout.block_slots + bases[family],
                    family_slots,
                );
            }
        }
    }

    // ===================================================================
    // Exact-state families.  All 2T slot-leaf sponge tiles fill their minimal
    // dyadic block-meta region contiguously (the tail is canonical sponge
    // ghosts); state Merkle paths retain their K-way chunking in walk B.
    // ===================================================================
    if let Some(e) = es {
        let n_es = e.leaves.len();
        let pad_flat = slot_leaf_pad_flat();
        let leaf_data: Vec<(F128, F128, F128)> = e
            .leaves
            .iter()
            .map(|l| (l.packed_value_flat, l.owner_hi_flat, l.owner_lo_flat))
            .collect();
        let es_w_log = es_region_slots.trailing_zeros() as usize;
        let (tc, tile_digests) = build_sponge_leaf_columns(&leaf_data, es_w_log);
        let base = es_meta_base;
        for j in 0..2 {
            meta_cols[IN0 + j][base..base + es_region_slots].copy_from_slice(&tc.in_[j]);
        }
        for j in 0..STATE_SIZE {
            meta_cols[C0 + j][base..base + es_region_slots].copy_from_slice(&tc.c[j]);
            meta_s0[j][base..base + es_region_slots].copy_from_slice(&tc.s0[j]);
            meta_s_out[j][base..base + es_region_slots].copy_from_slice(&tc.s_out[j]);
        }
        for (g, leaf) in e.leaves.iter().enumerate() {
            assert_eq!(
                tile_digests[g], leaf.expected_leaf_flat,
                "es sponge tile digest != the statement's expected leaf"
            );
            let off = base + g * SPONGE_LEAF_SLOTS;
            // Statement wires pinned to the committed absorb cells; the PAD
            // lane is a protocol constant (`pad_after_one_field`).
            cell_pins_meta.push((IN0, off, leaf.packed_value_w.clone()));
            cell_pins_meta.push((IN0 + 1, off, leaf.owner_hi_w.clone()));
            cell_pins_meta.push((IN0, off + 1, leaf.owner_lo_w.clone()));
            cell_pins_meta.push((IN0 + 1, off + 1, LinExpr::constant(pad_flat)));
            // Digest cells == the expected-leaf statement wires — the SAME
            // wires the state leg reads as its Merkle entries.
            let dslot = off + SPONGE_LEAF_DIGEST_SLOT;
            cell_pins_meta.push((C0, dslot, leaf.expected_leaf_w[0].clone()));
            cell_pins_meta.push((C0 + 1, dslot, leaf.expected_leaf_w[1].clone()));
        }

        if let Some(state_leg) = es_state_leg {
            assert_eq!(e.paths.len(), n_es, "one state path per slot leaf");
            let state_cap = leg_caps[state_leg];
            for blk in 0..k {
                let lo = (blk * state_cap).min(n_es);
                let hi = ((blk + 1) * state_cap).min(n_es);
                // --- Walk B: this block's state-path chunk;
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
                    &mut cb_meta_b,
                    &mut s0_meta_b,
                    &mut sout_meta_b,
                    &mut acc_entry_wires[state_leg],
                    &mut acc_root_wires[state_leg],
                    &mut acc_committed_roots[state_leg],
                    &mut acc_path_slots[state_leg],
                    &mut acc_recomputed_roots[state_leg],
                    e.d_state,
                    state_cap,
                    leg_ivs[state_leg],
                    4,
                    blk * meta_b.as_ref().expect("state leg needs meta-B").block_slots
                        + meta_bases[state_leg],
                    &state_paths,
                );
            }
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
        let txr_leg = txr_leg.expect("tx-root leg index");
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
            let region_base = blk
                * meta_b
                    .as_ref()
                    .expect("tx-root leg needs meta-B")
                    .block_slots
                + meta_bases[txr_leg];
            fill_es_merkle_leg(
                &mut cb_meta_b,
                &mut s0_meta_b,
                &mut sout_meta_b,
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
                    cell_pins_meta_b.push((
                        d_col,
                        base + 2 * level,
                        LinExpr::constant(if bit { F128::ONE } else { F128::ZERO }),
                    ));
                }
                if !t.rim_flat.is_empty() && j == n_paths - 1 {
                    for level in 0..t.depth {
                        if (j >> level) & 1 == 0 {
                            for lane in 0..2 {
                                cell_pins_meta_b.push((
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
    // per instance, one 32-slot compress tree plus one independent wrap slot
    // fill block-meta A's spine region. Real instances pin all sixteen raw body-leaf
    // statement pairs directly to the tree KID leaf cells, feed the tree root
    // into the TAG_TX8X2 wrap, and pin its digest to the tx-hash statement.
    // Ghost instances are the deterministic all-zero raw-leaf body; nothing
    // downstream reads their digest.
    // ===================================================================
    if let Some(sp) = spine {
        let n_inst = sp.instances.len();
        for blk in 0..k {
            for i in 0..spine_cap {
                let g = blk * spine_cap + i;
                let inst_flat = sp
                    .instances
                    .get(g)
                    .map(|inst| inst.flat.clone())
                    .unwrap_or_else(SpineInstanceFlat::ghost);
                let icols = build_spine_instance_columns(&inst_flat);
                let tree_abs =
                    spine_meta_base + blk * spine_per_tx + spine_tree_base + i * SPINE_TREE_SLOTS;
                let wrap_abs =
                    spine_meta_base + blk * spine_per_tx + spine_wrap_base + i * SPINE_WRAP_SLOTS;
                for j in 0..STATE_SIZE {
                    meta_cols[C0 + j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_c[j]);
                    meta_s0[j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_s0[j]);
                    meta_s_out[j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_s_out[j]);
                    meta_cols[C0 + j][wrap_abs..wrap_abs + SPINE_WRAP_SLOTS]
                        .copy_from_slice(&icols.wrap_c[j]);
                    meta_s0[j][wrap_abs..wrap_abs + SPINE_WRAP_SLOTS]
                        .copy_from_slice(&icols.wrap_s0[j]);
                    meta_s_out[j][wrap_abs..wrap_abs + SPINE_WRAP_SLOTS]
                        .copy_from_slice(&icols.wrap_s_out[j]);
                }
                for lane in 0..2 {
                    meta_cols[KID0 + lane][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_kid[lane]);
                    meta_cols[IN0 + lane][wrap_abs..wrap_abs + SPINE_WRAP_SLOTS]
                        .copy_from_slice(&icols.wrap_in[lane]);
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
                // Every raw statement leaf feeds the corresponding external
                // KID position. There is no record-leaf hash family.
                for (leaf, wpair) in inst.leaves_w.iter().enumerate() {
                    let kslot = tree_abs + SPINE_TREE_KID_LEAF_BASE + leaf;
                    cell_pins_meta.push((KID0, kslot, wpair[0].clone()));
                    cell_pins_meta.push((KID0 + 1, kslot, wpair[1].clone()));
                }
                // Tree root → wrap IN (shared wire; the root cell is the
                // tree's C0/C1 at heap node 1's odd slot, index 3).
                for lane in 0..2 {
                    let w = LinExpr::from_wire(b.alloc_f128(icols.root[lane]));
                    cell_pins_meta.push((C0 + lane, tree_abs + 3, w.clone()));
                    cell_pins_meta.push((IN0 + lane, wrap_abs + SPINE_WRAP_SLOT, w));
                }
                // Wrap digest → the tx-hash statement wires.
                for lane in 0..2 {
                    cell_pins_meta.push((
                        C0 + lane,
                        wrap_abs + SPINE_WRAP_SLOT,
                        inst.tx_hash_w[lane].clone(),
                    ));
                }
            }
        }
    }

    assert!(
        all_expands_ok,
        "all real-sibling octopus expands returned non-empty paths"
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: native column assembly");

    // ===================================================================
    // Commit the already-filled native columns before symbolic query
    // algebra. Physical allocation is in descending domain order to avoid
    // paying a large alignment gap after a smaller family. Logical claim
    // order remains wallet-A -> optional meta-A -> wallet-B -> optional
    // meta-B via the vectors below.
    // ===================================================================
    const FAMILY_WALLET_A: u8 = 0;
    const FAMILY_META_A: u8 = 1;
    const FAMILY_WALLET_B: u8 = 2;
    const FAMILY_META_B: u8 = 3;
    let mut allocation_order = vec![
        (wallet_w_log, FAMILY_WALLET_A),
        (wallet_b.w_log, FAMILY_WALLET_B),
    ];
    if has_meta {
        allocation_order.push((meta_w_log, FAMILY_META_A));
    }
    if let Some(layout) = meta_b.as_ref() {
        allocation_order.push((layout.w_log, FAMILY_META_B));
    }
    allocation_order.sort_by(|a, b_| b_.0.cmp(&a.0).then(a.1.cmp(&b_.1)));

    let mut wallet_slices: Option<Vec<WitnessSlice>> = None;
    let mut meta_slices: Vec<WitnessSlice> = Vec::new();
    let mut wallet_b_slices: Option<Vec<WitnessSlice>> = None;
    let mut meta_b_slices: Vec<WitnessSlice> = Vec::new();
    for (_, family) in allocation_order {
        match family {
            FAMILY_WALLET_A => {
                wallet_slices = Some(
                    wallet_cols
                        .iter()
                        .map(|c| alloc_column_slice(b, c, wallet_w_log).0)
                        .collect(),
                );
                crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-A wallet columns");
            }
            FAMILY_META_A => {
                meta_slices = meta_cols
                    .iter()
                    .map(|c| alloc_column_slice(b, c, meta_w_log).0)
                    .collect();
                crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-A meta columns");
            }
            FAMILY_WALLET_B => {
                wallet_b_slices = Some(
                    cb_wallet_b
                        .iter()
                        .enumerate()
                        .map(|(column, c)| {
                            if column == 8 {
                                alloc_boolean_column_slice(b, c, wallet_b.w_log).0
                            } else {
                                alloc_column_slice(b, c, wallet_b.w_log).0
                            }
                        })
                        .collect(),
                );
                crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: wallet-B columns");
            }
            FAMILY_META_B => {
                let layout = meta_b.as_ref().expect("meta-B allocation layout");
                meta_b_slices = cb_meta_b
                    .iter()
                    .map(|c| alloc_column_slice(b, c, layout.w_log).0)
                    .collect();
                crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: meta-B columns");
            }
            _ => unreachable!(),
        }
    }
    let wallet_slices = wallet_slices.expect("wallet slices allocated");
    let wallet_b_slices = wallet_b_slices.expect("wallet-B slices allocated");
    let mut slices = wallet_slices.clone();
    let n_slices_wallet = slices.len();
    slices.extend(meta_slices.iter().copied());
    let wallet_b_slice_base = slices.len();
    slices.extend(wallet_b_slices.iter().copied());
    let meta_b_slice_base = slices.len();
    slices.extend(meta_b_slices.iter().copied());

    let paired_handoff = paired_es.map(|paired| {
        let layout = meta_b.as_ref().expect("paired carrier needs meta-B slices");
        let bases = paired_bases.expect("paired family bases");
        let caps = paired_caps_per_block.expect("paired family capacities");
        pin_paired_consistency_cells(b, &meta_b_slices, layout, bases, caps);
        pin_paired_overhang_ghost_cells(
            b,
            &meta_b_slices,
            layout,
            bases,
            caps,
            [paired.touched_capacity, paired.segment_capacity],
            iv_flat_of_tag(TAG_EXSTNOD),
        );
        paired_exact_state_cells(&meta_b_slices, layout, bases, caps, paired)
    });
    if paired_handoff.is_some() {
        crate::acceptance::row_ledger_mark(
            b,
            &mut ledger,
            "plural: paired exact copy/ghost equalities",
        );
    }

    // ===================================================================
    // Symbolic phase. Transcript/query bits remain witness-backed, while
    // capsule symbols are read directly from wallet-A IN cells and each leaf
    // digest is joined to the walk-B CR/E start cell by one direct equality.
    // ===================================================================
    for tx in 0..k {
        let obligation = &obligations[tx];
        let native = &natives[tx];
        let opening = &native.opening;
        let tx_off_wallet = tx * wallet_per_tx;
        let tx_off_wallet_b = tx * wallet_b.block_slots;
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

        // Walk-C stays witness-backed in this cut. Its cells are pinned after
        // the duplex union is allocated below.
        let value_w = alloc_blocks(b, std::slice::from_ref(&opening.value))[0].clone();
        let upper = alloc_blocks(b, &opening.upper_partial_evals);
        let h_evals_w = alloc_blocks(b, &opening.h_evals);
        let mid_root_w = alloc_digest_raw(b, &opening.mid_root);
        let nonce_block = Block128::from(opening.grind_nonce as u128);
        let nonce_w = alloc_blocks(b, std::slice::from_ref(&nonce_block))[0].clone();
        let schedule = capsule_pcs_channel_schedule(native, num_vars, &point);
        assert_eq!(
            schedule.data_flat, chan_data_streams[tx],
            "native/symbolic channel schedule"
        );
        let dcols = build_duplex_columns(&chan_layout, iv_c, &schedule.data_flat, block_log_c);
        let chal_w: Vec<LinExpr> = dcols
            .challenges
            .iter()
            .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
            .collect();
        let query_seed_count = capsule_query_seed_count(num_vars + CAPSULE_LOG_RATE);
        assert_eq!(
            chal_w.len(),
            CAPSULE_TAU + 1 + query_seed_count,
            "channel challenge count"
        );
        let beta: Vec<LinExpr> = chal_w[..CAPSULE_TAU].to_vec();
        let grind_chal = chal_w[CAPSULE_TAU].clone();
        let query_seeds: Vec<LinExpr> = chal_w[CAPSULE_TAU + 1..].to_vec();

        let mut data_wires: Vec<LinExpr> = Vec::with_capacity(schedule.data_flat.len());
        for lane in &obligation.commitment_cap_lanes {
            data_wires.push(lane[0].clone());
            data_wires.push(lane[1].clone());
        }
        data_wires.push(value_w.clone());
        data_wires.extend(point_w.iter().cloned());
        data_wires.extend(upper.iter().cloned());
        data_wires.push(mid_root_w[0].clone());
        data_wires.push(mid_root_w[1].clone());
        data_wires.extend(h_evals_w.iter().cloned());
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
        chan_chal_wires.push(chal_w);
        chan_data_wires.push(data_wires);

        // Grind and packed query positions stay witness-bit decompositions.
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
        let query_width = num_vars + CAPSULE_LOG_RATE;
        let bound_query_bits = (0..CAPSULE_NUM_QUERIES)
            .map(|query| {
                (0..query_width)
                    .map(|query_bit| {
                        (query < nq).then(|| {
                            let slot = wallet_query_bit_slot(
                                tx_off_wallet_b,
                                ff_bases,
                                ff_strides,
                                ff_depths,
                                query,
                                query_bit,
                                num_vars,
                            );
                            slot_cell(&wallet_b_slices[8], slot)
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let (query_indices, query_bits) = packed_capsule_queries_from_seeds_with_bound_bits(
            b,
            &query_seeds,
            query_width,
            Some(&bound_query_bits),
        );
        assert!(query_indices.len() >= nq, "need at least nq queries");
        assert_eq!(
            query_indices,
            derive_queries(native, &point),
            "walk-C queries match native"
        );
        // Bit 0 drives both paths. All other query bits have one physical D
        // carrier; this is the sole exact cell-to-cell copy relation.
        for query in 0..nq {
            let primary = wallet_query_bit_slot(
                tx_off_wallet_b,
                ff_bases,
                ff_strides,
                ff_depths,
                query,
                0,
                num_vars,
            );
            let duplicate =
                wallet_query_bit0_duplicate_slot(tx_off_wallet_b, ff_bases, ff_strides, query);
            pin_eq(
                b,
                &slot_cell(&wallet_b_slices[8], primary),
                &slot_cell(&wallet_b_slices[8], duplicate),
            );
        }

        // Capsule opening reduction checks.
        let (x_low_w, x_top_w) = point_w.split_at(low_vars);
        let derived = mle_evaluate_small_trace(b, &upper, x_top_w);
        pin_eq(b, &derived, &value_w);
        let batched = mle_evaluate_small_trace(b, &upper, &beta);
        let h_at_xlow = mle_evaluate_small_trace(b, &h_evals_w, x_low_w);
        pin_eq(b, &batched, &h_at_xlow);
        pin_eq(b, &value_w, &obligation.reduction.value);
        assert_eq!(h_evals_w.len(), 2, "owner-auth capsule h shape");

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

        for q in 0..nq {
            let bits = &query_bits[q];
            let rc_bits = &bits[num_vars..num_vars + CAPSULE_LOG_RATE];
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
            let src_tile = tx_off_wallet + leaf_base(0) + q * leaf_stride;
            let mid_tile = tx_off_wallet + leaf_base(1) + q * leaf_stride;

            // Tile metadata still binds the transcript-derived leaf index.
            cell_pins_wallet.push((
                WALLET_IN0,
                src_tile,
                LinExpr::constant(raw_flat_lane(num_vars as u128)),
            ));
            cell_pins_wallet.push((WALLET_IN0 + 1, src_tile, raw_lane_from_bits(&src_leaf_bits)));
            cell_pins_wallet.push((
                WALLET_IN0,
                mid_tile,
                LinExpr::constant(raw_flat_lane(mid_log as u128)),
            ));
            cell_pins_wallet.push((WALLET_IN0 + 1, mid_tile, raw_lane_from_bits(&mid_leaf_bits)));

            // No duplicate symbol witnesses: folds consume the committed IN
            // cells directly.
            let src_syms_w = capsule_symbol_cells(&wallet_slices, src_tile);
            let mid_syms_w = capsule_symbol_cells(&wallet_slices, mid_tile);
            let rc_tensor = bit_eq_tensor(b, rc_bits);
            let folded = capsule_fold16_trace(b, &wide_hi, &rc_tensor, num_vars, &src_syms_w);
            let sel_mid = select_by_bits(b, mid_member_bits, &mid_syms_w);
            pin_eq(b, &folded, &sel_mid);
            let folded2 = capsule_fold16_trace(b, &wide_lo, &rc_tensor, mid_log, &mid_syms_w);
            let sel_code = select_rate2_capsule_code(b, &h_evals_w, &mid_leaf_bits, &rc_tensor);
            pin_eq(b, &folded2, &sel_code);

            // Direct wallet-A digest -> walk-B CR/E start equality. This one
            // row replaces a fresh bridge wire plus its two cell pins.
            let s_slot = tx_off_wallet_b + ff_bases[0] + q * ff_strides[0];
            let m_slot = tx_off_wallet_b + ff_bases[1] + q * ff_strides[1];
            pin_capsule_digest_bridges(
                b,
                &wallet_slices,
                &wallet_b_slices,
                [src_tile, mid_tile],
                [s_slot, m_slot],
            );
            let cap_root =
                std::array::from_fn(|lane| mle_evaluate_small_trace(b, &cap_lanes[lane], rc_bits));
            ff_root_copy_pins.push((s_slot + depth_s, cap_root));
            ff_root_copy_pins.push((
                m_slot + depth_m,
                [mid_root_w[0].clone(), mid_root_w[1].clone()],
            ));
        }
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: per-tx algebra loop");

    if preparing {
        assert!(
            has_both_meta_families,
            "production auth-PCS preparation requires exact-state and spine meta-A families"
        );
        assert!(
            txr.is_some(),
            "production auth-PCS preparation requires the tx-root meta-B family"
        );
        let meta_b_layout = meta_b
            .as_ref()
            .expect("production auth-PCS preparation requires meta-B");
        let paired_caps = paired_caps_per_block
            .expect("production auth-PCS preparation requires paired exact-state");
        let paired_offsets =
            paired_bases.expect("production auth-PCS preparation requires paired family bases");

        // The legacy trace verifier used to discover these entry/root pins as
        // a side effect of discharging the two-permutation families.  The
        // recording-free path derives the identical pins directly from the
        // already assembled typed family data.
        append_meta_b_statement_pins(
            &mut cell_pins_meta_b,
            &leg_depths,
            &acc_entry_wires,
            &acc_root_wires,
            &acc_committed_roots,
            &acc_recomputed_roots,
            &acc_path_slots,
        );
        pin_stage2_cells(b, &wallet_slices, &cell_pins_wallet);
        pin_stage2_cells(b, &meta_slices, &cell_pins_meta);
        pin_stage2_cells(b, &wallet_b_slices, &cell_pins_wallet_b);
        pin_stage2_cells(b, &meta_b_slices, &cell_pins_meta_b);
        pin_wallet_b_root_cells(b, &wallet_b_slices, &ff_root_copy_pins);
        crate::acceptance::row_ledger_mark(
            b,
            &mut ledger,
            "plural: recording-free stage-2 A/B cell pins",
        );

        // Main C contains only the K FRICHANL blocks.  There is no recorder
        // region, no C-discharge transcript, and consequently no D host.
        let main_c = build_duplex_union(&chan_layout, iv_c, &chan_data_streams);
        let main_c_slices: Vec<WitnessSlice> = main_c
            .committed
            .iter()
            .map(|column| alloc_column_slice(b, column, main_c.w_log).0)
            .collect();
        pin_main_c_channel_cells(
            b,
            &main_c,
            &main_c_slices,
            &chan_chal_wires,
            &chan_data_wires,
            &chan_data_positions,
        );
        crate::acceptance::row_ledger_mark(
            b,
            &mut ledger,
            "plural: recording-free main-C columns + exact pins",
        );

        let wallet_a_slice_array: [WitnessSlice; 6] = wallet_slices
            .as_slice()
            .try_into()
            .expect("six wallet-A slices");
        let meta_a_slice_array: [WitnessSlice; 8] = meta_slices
            .as_slice()
            .try_into()
            .expect("eight meta-A slices");
        let wallet_b_slice_array: [WitnessSlice; 9] = wallet_b_slices
            .as_slice()
            .try_into()
            .expect("nine wallet-B slices");
        let meta_b_slice_array: [WitnessSlice; 9] = meta_b_slices
            .as_slice()
            .try_into()
            .expect("nine meta-B slices");
        let main_c_slice_array: [WitnessSlice; 6] = main_c_slices
            .as_slice()
            .try_into()
            .expect("six main-C slices");

        let wallet_a_vk = crate::region_sidecar::WalkARegionVk::new_wallet(
            auth_pcs_wallet_a_sidecar_purpose(),
            k.trailing_zeros() as usize,
            nq.trailing_zeros() as usize,
            wallet_a_slice_array,
        )
        .expect("canonical wallet-A sidecar VK");
        let meta_a_vk = crate::region_sidecar::WalkARegionVk::new_meta(
            auth_pcs_meta_a_sidecar_purpose(),
            k.trailing_zeros() as usize,
            Some(es_region_slots.trailing_zeros() as usize),
            Some(spine_cap.trailing_zeros() as usize),
            meta_a_slice_array,
        )
        .expect("canonical meta-A sidecar VK");

        let wallet_b_families = (0..2)
            .map(
                |family| crate::region_sidecar::MerkleRegionFamily::FeedForward {
                    offset: ff_bases[family],
                    depth: ff_depths[family],
                    n_paths: nq,
                    iv: iv_capsnode,
                },
            )
            .collect();
        let wallet_b_vk = crate::region_sidecar::MerkleRegionVk::new(
            auth_pcs_wallet_b_sidecar_purpose(),
            wallet_b.w_log,
            wallet_b_slice_array,
            wallet_b.block_log,
            wallet_b_families,
        )
        .expect("canonical wallet-B sidecar VK");

        let paired_iv = iv_flat_of_tag(TAG_EXSTNOD);
        let mut meta_b_families = Vec::with_capacity(2 + n_legs);
        for family in 0..2 {
            meta_b_families.push(crate::region_sidecar::MerkleRegionFamily::PairedUpdate {
                offset: paired_offsets[family],
                n_updates: paired_caps[family],
                iv: paired_iv,
            });
        }
        for family in 0..n_legs {
            meta_b_families.push(crate::region_sidecar::MerkleRegionFamily::TwoPermutation {
                offset: meta_bases[family],
                depth: leg_depths[family],
                n_paths: leg_caps[family],
                iv: leg_ivs[family],
            });
        }
        let meta_b_vk = crate::region_sidecar::MerkleRegionVk::new(
            auth_pcs_meta_b_sidecar_purpose(),
            meta_b_layout.w_log,
            meta_b_slice_array,
            meta_b_layout.block_log,
            meta_b_families,
        )
        .expect("canonical meta-B sidecar VK");
        let main_c_vk = crate::region_sidecar::DuplexRegionVk::from_union(
            auth_pcs_main_c_sidecar_purpose(),
            main_c_slice_array,
            &main_c,
        )
        .expect("canonical recording-free main-C sidecar VK");

        return AuthPcsRegionAssemblyResult::Preparation(AuthPcsRegionPreparation {
            wallet_a_vk,
            wallet_a_endpoints: crate::region_sidecar::RegionWalkEndpoints::new(
                wallet_s0,
                wallet_s_out,
            ),
            meta_a_vk,
            meta_a_endpoints: crate::region_sidecar::RegionWalkEndpoints::new(meta_s0, meta_s_out),
            wallet_b_vk,
            wallet_b_endpoints: crate::region_sidecar::RegionWalkEndpoints::new(
                s0_wallet_b,
                sout_wallet_b,
            ),
            meta_b_vk,
            meta_b_endpoints: crate::region_sidecar::RegionWalkEndpoints::new(
                s0_meta_b,
                sout_meta_b,
            ),
            main_c_vk,
            main_c_endpoints: crate::region_sidecar::RegionWalkEndpoints::new(
                main_c.s0,
                main_c.s_out,
            ),
            paired: paired_handoff
                .expect("production auth-PCS preparation requires paired cell handoff"),
        });
    }

    // ===================================================================
    // Wallet walk A (once): exactly the two capsule-leaf families over K
    // txs, on six IN/C columns and the natural K*(2*nq*16) domain.
    // ===================================================================
    let mut fixed_wallet: Vec<FixedPattern> = Vec::new();
    let iv_capsleaf = capsule_leaf_iv_flat();
    // Each capsule-leaf family rides the region-gated SPONGE term shape
    // (region-gated plain IN reads, CARRY as the duplex feed-forward
    // selector, the slot-0 IV patterns).
    let mut wallet_leaf_refs: Vec<(SpongeLeafRefs, usize)> = Vec::with_capacity(n_leaf_families);
    for f in 0..n_leaf_families {
        let base = fixed_wallet.len();
        fixed_wallet.push(common_period_ones(
            leaf_base(f),
            nq * leaf_stride,
            wallet_block_log,
        ));
        for pat in capsule_leaf_fixed_patterns(iv_capsleaf) {
            fixed_wallet.push(common_period_pattern(
                &pat.table,
                leaf_base(f),
                nq,
                wallet_block_log,
            ));
        }
        wallet_leaf_refs.push((
            SpongeLeafRefs {
                in_: [WALLET_IN0, WALLET_IN0 + 1],
                c: std::array::from_fn(|i| WALLET_C0 + i),
                odd: base + 1, // the CARRY duplex selector
                iv: [base + 2, base + 3],
            },
            base, // the family's region gate
        ));
    }
    let wallet_meta_c: [usize; STATE_SIZE] = std::array::from_fn(|i| WALLET_C0 + i);
    let wallet_committed: Vec<&[F128]> = wallet_cols.iter().map(|c| c.as_slice()).collect();
    let native_wallet = run_union_native(
        &wallet_committed,
        &wallet_s0,
        &wallet_s_out,
        &fixed_wallet,
        &wallet_meta_c,
        &wallet_leaf_refs,
        None,
        None,
        None,
        wallet_w_log,
        DOMAIN_A_WALLET,
    );
    let mut ch_wallet = FsChannelUnionRecorder::new(DOMAIN_A_WALLET);
    claims.extend(discharge_union(
        b,
        &mut ch_wallet,
        &fixed_wallet,
        &wallet_meta_c,
        &wallet_leaf_refs,
        None,
        None,
        wallet_w_log,
        &native_wallet,
    ));
    let rec_wallet = ch_wallet.finish();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-A wallet twin");

    // ===================================================================
    // Block-meta walk A (optional, once): EXSTSLT and spine occupy separate
    // aligned dyadic regions and share the full eight KID/IN/C columns only
    // on this compact domain.  It has its own FS domain and recording.
    // ===================================================================
    let mut rec_meta: Option<RecordedChannel> = None;
    if has_meta {
        let mut fixed_meta: Vec<FixedPattern> = Vec::new();
        let es_sponge: Option<(SpongeLeafRefs, usize)> = es.map(|_| {
            let base = fixed_meta.len();
            fixed_meta.push(pattern_in_dyadic_region(
                FixedPattern::new(0, vec![F128::ONE]),
                es_meta_base,
                es_region_slots,
                meta_w_log,
            ));
            for pat in sponge_leaf_fixed_patterns(slot_leaf_iv_flat()) {
                fixed_meta.push(pattern_in_dyadic_region(
                    pat,
                    es_meta_base,
                    es_region_slots,
                    meta_w_log,
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
        let spine_refs: Option<(SourceTreeRefs, SpongeLeafRefs, usize)> = spine.map(|_| {
            let base = fixed_meta.len();
            for pat in spine_tree_fixed_patterns() {
                let tiled =
                    common_period_pattern(&pat.table, spine_tree_base, spine_cap, spine_block_log);
                fixed_meta.push(pattern_in_dyadic_region(
                    tiled,
                    spine_meta_base,
                    spine_region_slots,
                    meta_w_log,
                ));
            }
            for pat in spine_wrap_fixed_patterns() {
                let tiled =
                    common_period_pattern(&pat.table, spine_wrap_base, spine_cap, spine_block_log);
                fixed_meta.push(pattern_in_dyadic_region(
                    tiled,
                    spine_meta_base,
                    spine_region_slots,
                    meta_w_log,
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
                    odd: base + 6,
                    iv: [base + 7, base + 8],
                },
                base + 5,
            )
        });
        let meta_c: [usize; STATE_SIZE] = std::array::from_fn(|i| C0 + i);
        let spine_union_spec: Option<SpineUnionSpec> =
            spine_refs.map(|(tree_refs, wrap_refs, wrap_region)| SpineUnionSpec {
                tree_refs,
                wrap_refs,
                wrap_region,
                kid_meta: [KID0, KID0 + 1],
                c_meta: [C0, C0 + 1],
                cap_log: spine_cap.trailing_zeros() as usize,
                tx_log: k.trailing_zeros() as usize,
                tree_base: spine_tree_base,
                block_log_a: spine_block_log,
                walk_high_bits: dyadic_region_bits(spine_meta_base, spine_region_slots, meta_w_log)
                    .into_iter()
                    .map(|bit| if bit { F128::ONE } else { F128::ZERO })
                    .collect(),
            });
        let spine_expo_cols: [&[F128]; 4] = [
            spine_expo_kid0.as_slice(),
            spine_expo_kid1.as_slice(),
            spine_expo_c0.as_slice(),
            spine_expo_c1.as_slice(),
        ];
        let meta_committed: Vec<&[F128]> = meta_cols.iter().map(|c| c.as_slice()).collect();
        let native_meta = run_union_native(
            &meta_committed,
            &meta_s0,
            &meta_s_out,
            &fixed_meta,
            &meta_c,
            &[],
            es_sponge.as_ref(),
            spine_union_spec.as_ref(),
            spine_union_spec.as_ref().map(|_| &spine_expo_cols),
            meta_w_log,
            DOMAIN_A_META,
        );
        let mut ch_meta = FsChannelUnionRecorder::new(DOMAIN_A_META);
        let mut meta_claims = discharge_union(
            b,
            &mut ch_meta,
            &fixed_meta,
            &meta_c,
            &[],
            es_sponge.as_ref(),
            spine_union_spec.as_ref(),
            meta_w_log,
            &native_meta,
        );
        for claim in &mut meta_claims {
            claim.slice += n_slices_wallet;
        }
        rec_meta = Some(ch_meta.finish());
        claims.extend(meta_claims);
        crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-A meta twin");
    }

    // ===================================================================
    // Wallet walk B (once): exactly the two feed-forward capsule legs over
    // all K txs. It has its own domain, transcript, recording, and slices.
    // ===================================================================
    let mut fixed_wallet_b: Vec<FixedPattern> = Vec::new();
    let mut wallet_ff_specs: Vec<FfLegSpec> = Vec::with_capacity(2);
    for f in 0..2 {
        let base = fixed_wallet_b.len();
        let family = FfMerklePathFamily {
            depth: ff_depths[f],
            n_paths: nq,
        };
        for pat in ff_merkle_fixed_patterns(&family, iv_capsnode) {
            fixed_wallet_b.push(common_period_pattern(
                &pat.table,
                ff_bases[f],
                nq,
                wallet_b.block_log,
            ));
        }
        fixed_wallet_b.push(common_period_ones(
            ff_bases[f],
            nq * ff_strides[f],
            wallet_b.block_log,
        ));
        wallet_ff_specs.push(FfLegSpec {
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
    let committed_wallet_b: Vec<&[F128]> = cb_wallet_b.iter().map(|c| c.as_slice()).collect();
    let native_wallet_b = run_merkle_union_native(
        &committed_wallet_b,
        &s0_wallet_b,
        &sout_wallet_b,
        &fixed_wallet_b,
        &cb_c,
        &wallet_ff_specs,
        &[],
        wallet_b.w_log,
        DOMAIN_B_WALLET,
    );
    let mut ch_wallet_b = FsChannelUnionRecorder::new(DOMAIN_B_WALLET);
    let (mut wallet_b_claims, wallet_b_discharge_pins) = discharge_merkle_union(
        b,
        &mut ch_wallet_b,
        &fixed_wallet_b,
        &cb_c,
        &wallet_ff_specs,
        &[],
        wallet_b.w_log,
        &native_wallet_b,
    );
    let rec_wallet_b = ch_wallet_b.finish();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: wallet-B twin");
    for c in &mut wallet_b_claims {
        c.slice += wallet_b_slice_base;
    }
    claims.extend(wallet_b_claims);
    cell_pins_wallet_b.extend(wallet_b_discharge_pins);

    // ===================================================================
    // Block-meta walk B (optional, once): legacy exact-state and tx-root
    // 2-permutation legs only. Its claims follow wallet-B's claims.
    // ===================================================================
    let mut rec_meta_b: Option<RecordedChannel> = None;
    if let Some(layout) = meta_b.as_ref() {
        let mut fixed_meta_b: Vec<FixedPattern> = Vec::new();
        let mut paired_specs: Vec<PairedMerkleSpec> = Vec::new();
        if let (Some(caps), Some(bases)) = (paired_caps_per_block, paired_bases) {
            let iv = iv_flat_of_tag(TAG_EXSTNOD);
            for family in 0..2 {
                let fixed_base = fixed_meta_b.len();
                for pattern in paired_merkle_update_fixed_patterns(iv) {
                    fixed_meta_b.push(common_period_pattern(
                        &pattern.table,
                        bases[family],
                        caps[family],
                        layout.block_log,
                    ));
                }
                fixed_meta_b.push(common_period_ones(
                    bases[family],
                    caps[family] * PAIRED_UPDATE_STRIDE,
                    layout.block_log,
                ));
                paired_specs.push(PairedMerkleSpec {
                    refs: paired_merkle_update_refs(0, fixed_base),
                    region: fixed_base + 11,
                });
            }
        }
        let mut meta_legs: Vec<MerkleLeg> = Vec::with_capacity(n_legs);
        for f in 0..n_legs {
            let depth = leg_depths[f];
            let fixed_base = fixed_meta_b.len();
            let family = MerklePathFamily {
                depth,
                n_paths: leg_caps[f],
            };
            for pat in merkle_fixed_patterns(&family, leg_ivs[f]) {
                fixed_meta_b.push(common_period_pattern(
                    &pat.table,
                    meta_bases[f],
                    leg_caps[f],
                    layout.block_log,
                ));
            }
            fixed_meta_b.push(common_period_ones(
                meta_bases[f],
                family.n_slots(),
                layout.block_log,
            ));
            meta_legs.push(MerkleLeg {
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
        let committed_meta_b: Vec<&[F128]> = cb_meta_b.iter().map(|c| c.as_slice()).collect();
        let native_meta_b = run_merkle_union_native_with_paired(
            &committed_meta_b,
            &s0_meta_b,
            &sout_meta_b,
            &fixed_meta_b,
            &cb_c,
            &[],
            &meta_legs,
            &paired_specs,
            layout.w_log,
            DOMAIN_B_META,
        );
        let mut ch_meta_b = FsChannelUnionRecorder::new(DOMAIN_B_META);
        let (mut meta_b_claims, meta_b_discharge_pins) = discharge_merkle_union_with_paired(
            b,
            &mut ch_meta_b,
            &fixed_meta_b,
            &cb_c,
            &[],
            &meta_legs,
            &paired_specs,
            layout.w_log,
            &native_meta_b,
        );
        rec_meta_b = Some(ch_meta_b.finish());
        crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: meta-B twin");
        for c in &mut meta_b_claims {
            c.slice += meta_b_slice_base;
        }
        claims.extend(meta_b_claims);
        cell_pins_meta_b.extend(meta_b_discharge_pins);
    }

    // Stage 2: resolve the per-cell reads/pins to R1CS constraints (pin_eq), NOT
    // link-IO opening claims. Each column is opened by its walk discharge (random
    // point), so every cell is bound (Schwartz-Zippel); pinning the algebra wire
    // to the cell binds it too, keeping the O(K) per-cell bindings out of the IO.
    // Logical slices are wallet-A, optional meta-A, wallet-B, optional meta-B.
    pin_stage2_cells(b, &wallet_slices, &cell_pins_wallet);
    pin_stage2_cells(b, &meta_slices, &cell_pins_meta);
    pin_stage2_cells(b, &wallet_b_slices, &cell_pins_wallet_b);
    pin_stage2_cells(b, &meta_b_slices, &cell_pins_meta_b);
    // Feed-forward root pins: NODENS extends the existing CR-chain one slot
    // into the spare stride tail, so the recomputed root is already one
    // committed CR cell. Bind that cell directly to the FS-observed root.
    pin_wallet_b_root_cells(b, &wallet_b_slices, &ff_root_copy_pins);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: stage-2 A/B cell pins");

    // ===================================================================
    // Walk C (once): REGION 1 tiles the K txs' FRICHANL transcript channels;
    // REGION 2 carries wallet-A / meta-A / wallet-B / meta-B / owner-auth
    // walk-C′ discharge TRANSCRIPT RECORDINGS as per-block chain blocks
    // (tx-count flat). The
    // squeezed challenges every consumer (per-tx algebra AND the walk twins)
    // used are bound to carry cells; the absorbed data to A-lane cells. Walk
    // C's OWN discharge transcript is recorded once and carried by the
    // recording-only walk D. D's own discharge stays inline: this is the one
    // permitted hosting level, with no self-hosting cycle.
    // ===================================================================
    let rec_iv = FsChannelUnionRecorder::capacity_iv_flat();
    let mut recordings: Vec<&RecordedChannel> = vec![&rec_wallet];
    if let Some(rc) = rec_meta.as_ref() {
        recordings.push(rc);
    }
    recordings.push(&rec_wallet_b);
    if let Some(rc) = rec_meta_b.as_ref() {
        recordings.push(rc);
    }
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

    // Record C's discharge on a throwaway builder before allocating D's
    // committed columns. The native proof fixes every recorded value, so this
    // scratch pass is deterministic and costs no rows in the real relation.
    // It breaks the construction-order dependency cleanly: D's columns can be
    // allocated on their natural m13 boundary, then the real C recorder below
    // must reproduce this schedule/data/post-state exactly.
    let rec_c_scratch = {
        let mut scratch = FieldR1csBuilder::new_witness_only();
        let mut ch = FsChannelUnionRecorder::new(DOMAIN_C);
        let scratch_claims = discharge_duplex_union(&mut scratch, &mut ch, &u_c, &native_c, 0);
        assert_eq!(
            scratch_claims.len(),
            native_c.pending.len(),
            "walk-C scratch claim count"
        );
        ch.finish()
    };
    let rec_c_layout = compile_duplex(&rec_c_scratch.ops);
    let u_d = build_duplex_union(
        &rec_c_layout,
        rec_iv,
        std::slice::from_ref(&rec_c_scratch.data_flat),
    );
    let native_d = run_duplex_union_native(&u_d, DOMAIN_D);

    let n_slices_ab = slices.len();
    let slices_c: Vec<WitnessSlice> = u_c
        .committed
        .iter()
        .map(|c| alloc_column_slice(b, c, u_c.w_log).0)
        .collect();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-C columns");
    let n_slices_abc = n_slices_ab + slices_c.len();
    let slices_d: Vec<WitnessSlice> = u_d
        .committed
        .iter()
        .map(|c| alloc_column_slice(b, c, u_d.w_log).0)
        .collect();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-D columns");

    // Real C discharge: verifier algebra is unchanged, but its FS operations
    // produce witness wires instead of 7,579 inline Poseidon permutations.
    // Exact parity with the pre-allocation scratch pass is a construction
    // invariant; the algebraic binding itself is provided by D below.
    let mut ch_c = FsChannelUnionRecorder::new(DOMAIN_C);
    let mut wc_claims = discharge_duplex_union(b, &mut ch_c, &u_c, &native_c, 0);
    let rec_c = ch_c.finish();
    assert_eq!(
        rec_c.ops, rec_c_scratch.ops,
        "walk-C recording schedule drift"
    );
    assert_eq!(
        rec_c.data_flat, rec_c_scratch.data_flat,
        "walk-C recording data drift"
    );
    assert_eq!(
        rec_c.post_state, rec_c_scratch.post_state,
        "walk-C recording post-state drift"
    );
    assert_eq!(rec_c.perms, rec_c_scratch.perms, "walk-C permutation drift");
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-C twin (recorded)");
    for c in wc_claims.iter_mut() {
        c.slice += n_slices_ab;
    }

    // D is a single schedule block, not a two-region union. At B255 the
    // compiled C recording occupies 7,579 live permutation slots and pads
    // canonically to 8,192. Its own transcript is the sole inline replay and
    // is deliberately not recorded again.
    let mut ch_d = FsChannelTrace::new(b, DOMAIN_D);
    let mut wd_claims = discharge_duplex_union(b, &mut ch_d, &u_d, &native_d, 0);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: walk-D twin (inline)");
    for c in wd_claims.iter_mut() {
        c.slice += n_slices_abc;
    }

    // Exact C-transcript -> D-cell binding. Every non-constant absorbed C
    // proof lane lands in D's A columns; every challenge consumed by C's
    // verifier algebra is the corresponding D carry cell. D's random-point
    // column openings plus its walk/substitution proof bind all remaining
    // cells, including fixed schedule constants and the canonical tail.
    assert_eq!(u_d.challenges.len(), 1, "one recording-only D block");
    assert_eq!(
        rec_c.challenge_wires.len(),
        rec_c_layout.challenges.len(),
        "walk-C recorded challenge count"
    );
    assert_eq!(
        rec_c.data_wires.len(),
        rec_c_layout.n_data,
        "walk-C recorded data count"
    );
    for (kk, &(slot, lane)) in rec_c_layout.challenges.iter().enumerate() {
        assert_eq!(
            rec_c.challenge_wires[kk].eval(b.values()),
            u_d.challenges[0][kk],
            "walk-C challenge {kk} != walk-D native cell"
        );
        pin_eq(
            b,
            &rec_c.challenge_wires[kk],
            &slot_cell(&slices_d[u_d.refs.c[lane]], slot),
        );
    }
    for (kk, &(slot, lane)) in duplex_data_positions(&rec_c_layout).iter().enumerate() {
        pin_eq(
            b,
            &rec_c.data_wires[kk],
            &slot_cell(&slices_d[u_d.refs.a[lane]], slot),
        );
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: C->D recording pins");
    // Stage 2: the per-tx channel absorbs + squeezed challenges are tied to the
    // walk-C A/C cells by R1CS constraint (`pin_eq`), NOT per-cell opening
    // claims. Every A/C column is opened by the walk-C discharge's
    // selection/substitution (O(1) per column, already in `wc_claims`), so its
    // MLE — hence every cell — is bound; pinning the algebra wire to the cell
    // binds it too. This keeps the O(K·(n_data+n_chal)) channel bindings out of
    // the link IO entirely (they become ~K·(n_data+n_chal) R1CS rows, the
    // accepted per-tx algebra cost), so the channel is tx-flat in the IO.
    pin_main_c_channel_cells(
        b,
        &u_c,
        &slices_c,
        &chan_chal_wires,
        &chan_data_wires,
        &chan_data_positions,
    );
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
    slices.extend(slices_d);
    claims.extend(wc_claims);
    claims.extend(wd_claims);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "plural: cell pins + recordings");

    // Keep the public-IO/native mirror order explicit across the physical
    // allocation reorder: wallet-A, optional meta-A, wallet-B, optional
    // meta-B, C, then D. Also assert trace/native claim parity before resolving
    // logical column indices into their actual witness slices.
    let claim_family = |slice: usize| {
        if slice < n_slices_wallet {
            0u8
        } else if slice < wallet_b_slice_base {
            1
        } else if slice < meta_b_slice_base {
            2
        } else if slice < n_slices_ab {
            3
        } else if slice < n_slices_abc {
            4
        } else {
            5
        }
    };
    let mut previous_family = 0u8;
    for (ci, claim) in claims.iter().enumerate() {
        let family = claim_family(claim.slice);
        assert!(
            family >= previous_family,
            "region claim family order drift at claim {ci}"
        );
        previous_family = family;
        assert_eq!(
            claim.point.len(),
            claim.native_point.len(),
            "region claim {ci} point arity parity"
        );
        for (coord, native) in claim.point.iter().zip(&claim.native_point) {
            assert_eq!(
                coord.eval(b.values()),
                *native,
                "region claim {ci} point parity"
            );
        }
        assert_eq!(
            claim.value.eval(b.values()),
            claim.native_value,
            "region claim {ci} value parity"
        );
    }

    // Resolve each claim's column index into its committed WitnessSlice.
    let claims = claims
        .into_iter()
        .map(|c| RegionPcsClaim {
            slice: slices[c.slice],
            point: c.point,
            value: c.value,
            native_point: c.native_point,
            native_value: c.native_value,
        })
        .collect();
    debug_assert!(
        !preparing,
        "preparation must return before legacy discharge"
    );
    AuthPcsRegionAssemblyResult::LegacyDischarge(AuthPcsRegionDischarge {
        claims,
        paired: paired_handoff,
    })
}

#[allow(clippy::too_many_arguments)]
fn append_meta_b_statement_pins(
    pins: &mut Vec<(usize, usize, LinExpr)>,
    leg_depths: &[usize],
    entry_wires: &[Vec<[LinExpr; 2]>],
    root_wires: &[Vec<[LinExpr; 2]>],
    committed_roots: &[Vec<[F128; 2]>],
    recomputed_roots: &[Vec<[F128; 2]>],
    path_slots: &[Vec<usize>],
) {
    for family in 0..leg_depths.len() {
        let n_paths = path_slots[family].len();
        assert_eq!(entry_wires[family].len(), n_paths, "meta-B entry count");
        assert_eq!(root_wires[family].len(), n_paths, "meta-B root count");
        assert_eq!(
            committed_roots[family].len(),
            n_paths,
            "meta-B committed-root count"
        );
        assert_eq!(
            recomputed_roots[family].len(),
            n_paths,
            "meta-B recomputed-root count"
        );
        let root_slot_local = 2 * (leg_depths[family] - 1) + 1;
        for path in 0..n_paths {
            let entry_slot = path_slots[family][path];
            for lane in 0..2 {
                pins.push((
                    4 + lane,
                    entry_slot,
                    entry_wires[family][path][lane].clone(),
                ));
                assert_eq!(
                    recomputed_roots[family][path][lane], committed_roots[family][path][lane],
                    "meta-B recomputed/committed root mismatch"
                );
                pins.push((
                    lane,
                    entry_slot + root_slot_local,
                    root_wires[family][path][lane].clone(),
                ));
            }
        }
    }
}

fn pin_stage2_cells(
    b: &mut FieldR1csBuilder,
    slices: &[WitnessSlice],
    pins: &[(usize, usize, LinExpr)],
) {
    for (column, slot, wire) in pins {
        pin_eq(b, wire, &slot_cell(&slices[*column], *slot));
    }
}

fn pin_wallet_b_root_cells(
    b: &mut FieldR1csBuilder,
    slices: &[WitnessSlice],
    root_pins: &[(usize, [LinExpr; 2])],
) {
    for (root_copy_slot, root_wires) in root_pins {
        for lane in 0..2 {
            pin_eq(
                b,
                &slot_cell(&slices[4 + lane], *root_copy_slot),
                &root_wires[lane],
            );
        }
    }
}

fn pin_main_c_channel_cells(
    b: &mut FieldR1csBuilder,
    union: &DuplexUnion,
    slices: &[WitnessSlice],
    challenge_wires: &[Vec<LinExpr>],
    data_wires: &[Vec<LinExpr>],
    data_positions: &[(usize, usize)],
) {
    assert_eq!(challenge_wires.len(), union.challenges.len());
    assert_eq!(data_wires.len(), union.challenges.len());
    let per_tx = 1usize << union.block_log;
    for tx in 0..challenge_wires.len() {
        assert_eq!(challenge_wires[tx].len(), union.layout.challenges.len());
        assert_eq!(data_wires[tx].len(), data_positions.len());
        for (wire, &(slot, lane)) in challenge_wires[tx].iter().zip(&union.layout.challenges) {
            let cell = slot_cell(&slices[union.refs.c[lane]], tx * per_tx + slot);
            pin_eq(b, wire, &cell);
        }
        for (wire, &(slot, lane)) in data_wires[tx].iter().zip(data_positions) {
            let cell = slot_cell(&slices[union.refs.a[lane]], tx * per_tx + slot);
            pin_eq(b, wire, &cell);
        }
    }
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

/// Domain-separated, class-independent purpose of the owner-auth C-prime
/// post-commit sidecar.  Callers never supply this value: every preparation
/// binds the same role identifier while the VK separately binds its exact
/// layout and witness slices.
const OWNER_AUTH_DUPLEX_SIDECAR_PURPOSE_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/OWNER-AUTH-C-PRIME/V1";

/// Canonical purpose committed by every owner-auth C-prime sidecar VK.
pub fn owner_auth_duplex_sidecar_purpose() -> [u8; 32] {
    noid_poseidon2b::native::poseidon2b_hash_byte_slices(
        OWNER_AUTH_DUPLEX_SIDECAR_PURPOSE_DOMAIN,
        &[OWNER_AUTH_DOMAIN_C],
    )
}

/// Owning production handoff for the owner-auth C-prime vertical.
///
/// The R1CS builder already contains the channel-independent owner algebra,
/// all six committed duplex columns, and every absorb/challenge cell pin.
/// The deep-chain endpoints remain native prover data and are deliberately
/// owned here rather than inserted into the pre-commit R1CS witness.  A block
/// prover turns them into a [`crate::region_sidecar::DuplexRegionProverPlan`]
/// only inside the enclosing FieldR1cs post-commit callback.
pub struct OwnerAuthDuplexRegionPreparation {
    pub obligations: Vec<PendingAuthPcsObligation>,
    pub duplex_vk: crate::region_sidecar::DuplexRegionVk,
    s0: [Vec<F128>; STATE_SIZE],
    s_out: [Vec<F128>; STATE_SIZE],
}

impl OwnerAuthDuplexRegionPreparation {
    pub fn s0(&self) -> &[Vec<F128>; STATE_SIZE] {
        &self.s0
    }

    pub fn s_out(&self) -> &[Vec<F128>; STATE_SIZE] {
        &self.s_out
    }

    pub fn prover_plan(
        &self,
    ) -> Result<
        crate::region_sidecar::DuplexRegionProverPlan<'_>,
        crate::region_sidecar::RegionSidecarError,
    > {
        crate::region_sidecar::DuplexRegionProverPlan::new(&self.duplex_vk, &self.s0, &self.s_out)
    }

    /// Consume the preparation at the block assembly boundary.  Obligations
    /// continue into the wallet-PCS algebra, while the canonical VK and native
    /// endpoints become the mandatory owner-C child of `BlockRegionPreparation`.
    pub fn into_block_parts(
        self,
    ) -> (
        Vec<PendingAuthPcsObligation>,
        crate::region_sidecar::DuplexRegionVk,
        crate::region_sidecar::RegionWalkEndpoints,
    ) {
        (
            self.obligations,
            self.duplex_vk,
            crate::region_sidecar::RegionWalkEndpoints::new(self.s0, self.s_out),
        )
    }
}

/// Internal phase boundary shared by the production preparation and the
/// transitional inline-discharge wrapper.  Constructing this object performs
/// no deep-chain proof, Fiat--Shamir replay, recording, or PCS-claim emission.
struct OwnerAuthDuplexRegionAssembly {
    obligations: Vec<PendingAuthPcsObligation>,
    union: DuplexUnion,
    slices: [WitnessSlice; 6],
    challenge_wires: Vec<Vec<LinExpr>>,
    data_wires: Vec<Vec<LinExpr>>,
}

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

/// Assemble K owner-authorization killshots and one shared KSCHANNL duplex
/// witness without choosing how that witness will be proven.  The returned
/// phase boundary owns the same reduced wallet-PCS obligations as the inline
/// twin plus the committed columns/endpoints needed by either finalizer.
///
/// Challenge order in the walk-C carry cells (`5·num_vars + 2 + L_b` total
/// with `L_b = rlc_levels(boundary constraints)`, class-fixed by
/// `owner_auth_channel_schedule`):
///   `[rho×nv, r_prime×nv, delta, r_double_prime×nv, boundary_bases×L_b,
///     boundary_point×nv, batch_alpha, r_B×nv]`.
/// The fold outputs `r_prime` / `r_double_prime` / `boundary_point` / `r_B` are
/// the REVERSE of their per-round challenge order (matching the inline twin).
fn assemble_owner_auth_killshots_via_region(
    b: &mut FieldR1csBuilder,
    trace_proofs: &[OwnerAuthProofTrace],
    trace_inputs: &[OwnerAuthPublicInputsTrace],
    native_proofs: &[OwnerAuthProofKillShot],
    native_inputs: &[OwnerAuthPublicInputs],
) -> OwnerAuthDuplexRegionAssembly {
    let k = trace_proofs.len();
    assert!(k >= 1, "at least one owner-auth killshot");
    assert_eq!(trace_inputs.len(), k, "one trace input per killshot");
    assert_eq!(native_proofs.len(), k, "one native proof per killshot");
    assert_eq!(native_inputs.len(), k, "one native input per killshot");

    // Class-fixed channel layout — tx 0 defines it; every tx shares the class.
    let num_vars = OWNER_AUTH_NUM_VARS;
    let chan_layout =
        compile_duplex(&owner_auth_channel_schedule(&native_proofs[0], &native_inputs[0]).ops);
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
    let union = build_duplex_union(&chan_layout, iv_c, &chan_data_streams);
    let slices: [WitnessSlice; 6] = std::array::from_fn(|column| {
        alloc_column_slice(b, &union.committed[column], union.w_log).0
    });

    OwnerAuthDuplexRegionAssembly {
        obligations,
        union,
        slices,
        challenge_wires: chan_chal_wires,
        data_wires: chan_data_wires,
    }
}

/// Add the exact owner-auth transcript-data and squeezed-challenge cell pins.
/// Keeping this finalizer separate lets the transitional path preserve its
/// historic row order (legacy discharge first, pins second), while production
/// preparation performs no such discharge at all.
fn pin_owner_auth_duplex_cells(b: &mut FieldR1csBuilder, assembly: &OwnerAuthDuplexRegionAssembly) {
    let union = &assembly.union;
    let data_positions = duplex_data_positions(&union.layout);
    let per_tx = 1usize << union.block_log;
    assert_eq!(
        assembly.challenge_wires.len(),
        assembly.data_wires.len(),
        "one owner-auth channel wire set per transaction"
    );
    for tx in 0..assembly.challenge_wires.len() {
        assert_eq!(
            assembly.challenge_wires[tx].len(),
            union.layout.challenges.len(),
            "owner-auth squeezed-challenge pin count"
        );
        assert_eq!(
            assembly.data_wires[tx].len(),
            data_positions.len(),
            "owner-auth absorb-data pin count"
        );
        for (wire, &(slot, lane)) in assembly.challenge_wires[tx]
            .iter()
            .zip(&union.layout.challenges)
        {
            let cell = slot_cell(&assembly.slices[union.refs.c[lane]], tx * per_tx + slot);
            pin_eq(b, wire, &cell);
        }
        for (wire, &(slot, lane)) in assembly.data_wires[tx].iter().zip(&data_positions) {
            let cell = slot_cell(&assembly.slices[union.refs.a[lane]], tx * per_tx + slot);
            pin_eq(b, wire, &cell);
        }
    }
}

/// Prepare the sound owner-auth C-prime post-commit vertical.
///
/// This path performs all existing owner algebra and exact cell pinning, but
/// deliberately does not construct a deep-chain proof, instantiate a
/// challenger/recorder, emit [`RegionPcsClaim`] values, or produce a recording
/// for another region to host.
pub fn prepare_owner_auth_killshots_via_region(
    b: &mut FieldR1csBuilder,
    trace_proofs: &[OwnerAuthProofTrace],
    trace_inputs: &[OwnerAuthPublicInputsTrace],
    native_proofs: &[OwnerAuthProofKillShot],
    native_inputs: &[OwnerAuthPublicInputs],
) -> OwnerAuthDuplexRegionPreparation {
    let assembly = assemble_owner_auth_killshots_via_region(
        b,
        trace_proofs,
        trace_inputs,
        native_proofs,
        native_inputs,
    );
    pin_owner_auth_duplex_cells(b, &assembly);
    let duplex_vk = crate::region_sidecar::DuplexRegionVk::from_union(
        owner_auth_duplex_sidecar_purpose(),
        assembly.slices,
        &assembly.union,
    )
    .expect("owner-auth C-prime is one canonical recording-free duplex union");

    OwnerAuthDuplexRegionPreparation {
        obligations: assembly.obligations,
        duplex_vk,
        s0: assembly.union.s0,
        s_out: assembly.union.s_out,
    }
}

/// Transitional pre-commit discharge retained for existing callers while the
/// block/link envelope migrates to [`prepare_owner_auth_killshots_via_region`].
/// New production code must use the preparation path above.
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
    let assembly = assemble_owner_auth_killshots_via_region(
        b,
        trace_proofs,
        trace_inputs,
        native_proofs,
        native_inputs,
    );
    let native = run_duplex_union_native(&assembly.union, OWNER_AUTH_DOMAIN_C);
    let mut recorder = FsChannelUnionRecorder::new(OWNER_AUTH_DOMAIN_C);
    let claims = discharge_duplex_union(b, &mut recorder, &assembly.union, &native, 0);
    pin_owner_auth_duplex_cells(b, &assembly);

    let region_claims = claims
        .into_iter()
        .map(|claim| RegionPcsClaim {
            slice: assembly.slices[claim.slice],
            point: claim.point,
            value: claim.value,
            native_point: claim.native_point,
            native_value: claim.native_value,
        })
        .collect();

    (assembly.obligations, region_claims, recorder.finish())
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

/// The unique wallet-B D-cell carrying one packed OwnerAuth query bit.
///
/// OwnerAuth is the fixed `nv=9`, rate-32 capsule shape, hence fourteen
/// position bits. The two depth-5/depth-6 paths both use stride eight:
/// source D[0..5] already carries bits 0..5, its three spare tail cells carry
/// bits 5..8; mid D[1..6] carries the five rate-coset bits 9..14, and its
/// root-copy tail D[6] carries bit 8. Mid D[0] is the one deliberate duplicate
/// of bit 0 and is joined by an exact equality in the caller.
fn wallet_query_bit_slot(
    tx_off: usize,
    ff_bases: [usize; 2],
    ff_strides: [usize; 2],
    ff_depths: [usize; 2],
    query: usize,
    query_bit: usize,
    num_vars: usize,
) -> usize {
    assert_eq!(num_vars, OWNER_AUTH_NUM_VARS, "OwnerAuth capsule nv");
    assert_eq!(
        OWNER_AUTH_NUM_VARS, 9,
        "query carrier layout must be revisited"
    );
    assert_eq!(ff_depths, [5, 6], "OwnerAuth ff depths");
    assert_eq!(ff_strides, [8, 8], "OwnerAuth ff strides");
    assert!(query_bit < num_vars + CAPSULE_LOG_RATE);

    let source = tx_off + ff_bases[0] + query * ff_strides[0];
    let mid = tx_off + ff_bases[1] + query * ff_strides[1];
    match query_bit {
        0..=7 => source + query_bit,
        8 => mid + ff_depths[1],
        9..=13 => mid + 1 + (query_bit - num_vars),
        _ => unreachable!("OwnerAuth has exactly fourteen query bits"),
    }
}

/// The second physical carrier of query bit 0: the mid path's level-0
/// direction. The primary carrier is source D[0].
fn wallet_query_bit0_duplicate_slot(
    tx_off: usize,
    ff_bases: [usize; 2],
    ff_strides: [usize; 2],
    query: usize,
) -> usize {
    tx_off + ff_bases[1] + query * ff_strides[1]
}

/// Fill every live/tail D carrier from the native packed query positions.
/// This runs before column allocation, so no extra witness cells are minted.
fn fill_wallet_query_bit_carriers(
    d_column: &mut [F128],
    tx_off: usize,
    ff_bases: [usize; 2],
    ff_strides: [usize; 2],
    ff_depths: [usize; 2],
    native_queries: &[usize],
    nq: usize,
    num_vars: usize,
) {
    let width = num_vars + CAPSULE_LOG_RATE;
    assert!(native_queries.len() >= nq);
    for (query, &index) in native_queries.iter().take(nq).enumerate() {
        for query_bit in 0..width {
            let slot = wallet_query_bit_slot(
                tx_off, ff_bases, ff_strides, ff_depths, query, query_bit, num_vars,
            );
            d_column[slot] = if (index >> query_bit) & 1 == 1 {
                F128::ONE
            } else {
                F128::ZERO
            };
        }
        let duplicate = wallet_query_bit0_duplicate_slot(tx_off, ff_bases, ff_strides, query);
        d_column[duplicate] = if index & 1 == 1 {
            F128::ONE
        } else {
            F128::ZERO
        };
    }
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
#[cfg(test)]
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

/// Select one cell of `Code(h)` for the fixed OwnerAuth `|h| = 2` shape.
///
/// For rate coset `c`, the additive two-point transform is
/// `[s, s * basis(c) + h1]`, where `s = h0 + h1`.  `rc_tensor` selects the
/// public basis constant linearly; one multiplication forms the odd cell and
/// one selects even/odd from the query's local bit.  This is byte-identical to
/// `capsule_encode_trace(h)[local + 2*c]` and costs two rows instead of the
/// generic 127-row 64-way selection.
fn select_rate2_capsule_code(
    b: &mut FieldR1csBuilder,
    h: &[LinExpr],
    leaf_bits: &[LinExpr],
    rc_tensor: &[LinExpr],
) -> LinExpr {
    assert_eq!(h.len(), 2, "rate-2 capsule message");
    assert_eq!(leaf_bits.len(), 1 + CAPSULE_LOG_RATE, "rate-2 leaf bits");
    assert_eq!(rc_tensor.len(), CAPSULE_RATE, "rate tensor");

    let mut basis = LinExpr::zero();
    for (coset, eq) in rc_tensor.iter().enumerate() {
        basis = basis.add(&eq.scale(flat_of(Block128::from(1u128 << coset))));
    }
    let even = h[0].add(&h[1]);
    let odd = mul(b, &even, &basis).add(&h[1]);
    even.add(&mul(b, &leaf_bits[0], &even.add(&odd)))
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

/// Final 31-permutation Tx8x2 spine handoff.  One instance per block
/// transaction (coinbase included), in transaction order.
pub struct SpineRegionData {
    pub instances: Vec<SpineInstanceRegion>,
}

/// One transaction's spine handoff: all sixteen canonical raw body leaves,
/// plus the tx-body hash pair consumed by the tx-root and owner-auth paths.
pub struct SpineInstanceRegion {
    pub flat: SpineInstanceFlat,
    pub leaves_w: [[LinExpr; 2]; SPINE_TREE_LEAVES],
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

/// Allocate one committed column as exact boolean R1CS rows while preserving
/// the same contiguous [`WitnessSlice`] geometry as [`alloc_column_slice`].
/// This is used by wallet-B's D column: live directions and packed-query tail
/// carriers are boolean by protocol, and their booleanity must not depend on a
/// pre-commit Fiat–Shamir relation challenge.
pub(crate) fn alloc_boolean_column_slice(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> (WitnessSlice, Vec<LinExpr>) {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    let wires = col
        .iter()
        .enumerate()
        .map(|(slot, &value)| {
            assert!(
                value == F128::ZERO || value == F128::ONE,
                "boolean column slot {slot}"
            );
            LinExpr::from_wire(b.alloc_bool(value == F128::ONE))
        })
        .collect::<Vec<_>>();
    for _ in col.len()..block {
        b.alloc_bool(false);
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

fn paired_update_base(
    layout: &TiledWalkLayout,
    family_base: usize,
    cap_per_block: usize,
    ordinal: usize,
) -> usize {
    let block = ordinal / cap_per_block;
    let within = ordinal % cap_per_block;
    let base = block * layout.block_slots + family_base + within * PAIRED_UPDATE_STRIDE;
    assert!(
        base + PAIRED_UPDATE_STRIDE <= layout.slots,
        "paired cell outside meta-B"
    );
    base
}

/// Exact (non challenge-mixed) copy constraints of the paired primitive:
/// old-even SIB/D → new-even and both lane bridges `E(w)=C(w-2)` on every
/// allocated local/upper update, including K-tile overhang ghosts.
fn pin_paired_consistency_cells(
    b: &mut FieldR1csBuilder,
    slices: &[WitnessSlice],
    layout: &TiledWalkLayout,
    family_bases: [usize; 2],
    caps_per_block: [usize; 2],
) {
    assert_eq!(slices.len(), 9, "paired meta-B slice count");
    let blocks = layout.slots / layout.block_slots;
    for block in 0..blocks {
        for family in 0..2 {
            for update in 0..caps_per_block[family] {
                let base = block * layout.block_slots
                    + family_bases[family]
                    + update * PAIRED_UPDATE_STRIDE;
                for level in 0..PAIRED_UPDATE_DEPTH {
                    let old_even = base + level * PAIRED_UPDATE_SLOTS_PER_LEVEL;
                    let new_even = old_even + 2;
                    for col in [6usize, 7, 8] {
                        pin_eq(
                            b,
                            &slot_cell(&slices[col], old_even),
                            &slot_cell(&slices[col], new_even),
                        );
                    }
                    for lane in 0..2 {
                        // new-odd E carries this level's old-odd C.
                        pin_eq(
                            b,
                            &slot_cell(&slices[4 + lane], old_even + 3),
                            &slot_cell(&slices[lane], old_even + 1),
                        );
                        if level > 0 {
                            // next old-odd E carries the previous new-odd C.
                            pin_eq(
                                b,
                                &slot_cell(&slices[4 + lane], old_even + 1),
                                &slot_cell(&slices[lane], old_even - 1),
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Bind the ceil-tiling suffix of each paired family to the native builder's
/// canonical ghost update. The fixed walk matrix remains class-constant: this
/// is a Stage-2 exact-cell hardening over only the non-exported update suffix.
///
/// One overhang update costs exactly `9 * PAIRED_UPDATE_STRIDE = 576` rows.
fn pin_paired_overhang_ghost_cells(
    b: &mut FieldR1csBuilder,
    slices: &[WitnessSlice],
    layout: &TiledWalkLayout,
    family_bases: [usize; 2],
    caps_per_block: [usize; 2],
    class_capacities: [usize; 2],
    iv_flat: [F128; 2],
) {
    assert_eq!(slices.len(), 9, "paired meta-B slice count");
    let blocks = layout.slots / layout.block_slots;
    let ghost = build_paired_merkle_update_columns(&[], iv_flat, 6);
    let ghost_committed = ghost.committed_columns();
    assert_eq!(ghost_committed.len(), slices.len(), "paired ghost columns");

    for family in 0..2 {
        assert_eq!(
            caps_per_block[family],
            class_capacities[family].div_ceil(blocks),
            "paired ceil-tiling capacity"
        );
        let tiled_capacity = blocks * caps_per_block[family];
        for ordinal in class_capacities[family]..tiled_capacity {
            let base = paired_update_base(
                layout,
                family_bases[family],
                caps_per_block[family],
                ordinal,
            );
            for (column, values) in ghost_committed.iter().enumerate() {
                for offset in 0..PAIRED_UPDATE_STRIDE {
                    pin_eq(
                        b,
                        &slot_cell(&slices[column], base + offset),
                        &LinExpr::constant(values[offset]),
                    );
                }
            }
        }
    }
}

fn paired_exact_state_cells(
    slices: &[WitnessSlice],
    layout: &TiledWalkLayout,
    family_bases: [usize; 2],
    caps_per_block: [usize; 2],
    paired: &ExactStatePairedRegionData,
) -> PairedExactStateCells {
    assert_eq!(slices.len(), 9, "paired meta-B slice count");
    let entries = |base: usize| {
        (
            std::array::from_fn(|lane| slot_cell(&slices[4 + lane], base)),
            std::array::from_fn(|lane| slot_cell(&slices[4 + lane], base + 2)),
        )
    };
    let directions = |base: usize| {
        std::array::from_fn(|level| {
            slot_cell(&slices[8], base + level * PAIRED_UPDATE_SLOTS_PER_LEVEL)
        })
    };
    let roots_at = |base: usize, depth: usize| {
        let [old, new] = paired_update_root_offsets(depth);
        (
            std::array::from_fn(|lane| slot_cell(&slices[lane], base + old)),
            std::array::from_fn(|lane| slot_cell(&slices[lane], base + new)),
        )
    };

    let local = (0..paired.touched_capacity)
        .map(|ordinal| {
            let base = paired_update_base(layout, family_bases[0], caps_per_block[0], ordinal);
            let (old_entry, new_entry) = entries(base);
            let (old_root, new_root) = roots_at(base, PAIRED_UPDATE_DEPTH);
            PairedLocalExactStateCells {
                old_entry,
                new_entry,
                old_root,
                new_root,
                directions: directions(base),
            }
        })
        .collect();
    let upper = (0..paired.segment_capacity)
        .map(|ordinal| {
            let base = paired_update_base(layout, family_bases[1], caps_per_block[1], ordinal);
            let (old_entry, new_entry) = entries(base);
            let root_pairs: [([LinExpr; 2], [LinExpr; 2]); PAIRED_UPDATE_DEPTH] =
                std::array::from_fn(|level| roots_at(base, level + 1));
            PairedUpperExactStateCells {
                old_entry,
                new_entry,
                old_roots: std::array::from_fn(|level| root_pairs[level].0.clone()),
                new_roots: std::array::from_fn(|level| root_pairs[level].1.clone()),
                directions: directions(base),
            }
        })
        .collect();
    PairedExactStateCells { local, upper }
}

/// The sixteen capsule symbols stored across the two wallet IN lanes at tile
/// slots 1..=8. These are expressions over the committed column wires, not
/// duplicate witnesses.
fn capsule_symbol_cells(wallet_slices: &[WitnessSlice], tile: usize) -> Vec<LinExpr> {
    assert_eq!(
        wallet_slices.len(),
        N_WALLET_COMMITTED,
        "wallet slice count"
    );
    (0..CAPSULE_LEAF_SYMBOLS)
        .map(|s| slot_cell(&wallet_slices[WALLET_IN0 + (s & 1)], tile + 1 + s / 2))
        .collect()
}

/// Bind source+mid wallet tile digests directly to the corresponding walk-B
/// CR/E start cells. Exactly four equality rows, with no bridge witnesses.
fn pin_capsule_digest_bridges(
    b: &mut FieldR1csBuilder,
    wallet_slices: &[WitnessSlice],
    b_slices: &[WitnessSlice],
    tiles: [usize; 2],
    starts: [usize; 2],
) {
    assert_eq!(
        wallet_slices.len(),
        N_WALLET_COMMITTED,
        "wallet slice count"
    );
    assert_eq!(b_slices.len(), 9, "walk-B slice count");
    for (tile, start) in tiles.into_iter().zip(starts) {
        for lane in 0..2 {
            let digest = slot_cell(
                &wallet_slices[WALLET_C0 + lane],
                tile + CAPSULE_LEAF_DIGEST_SLOT,
            );
            pin_eq(b, &digest, &slot_cell(&b_slices[4 + lane], start));
        }
    }
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

/// High index bits selecting one aligned dyadic sub-region of a walk domain.
/// Bits are returned LSB-first, starting immediately above the region-local
/// coordinates. An empty vector means the region is the whole domain.
pub(crate) fn dyadic_region_bits(base: usize, slots: usize, w_log: usize) -> Vec<bool> {
    assert!(slots.is_power_of_two(), "dyadic region size");
    let region_log = slots.trailing_zeros() as usize;
    assert!(region_log <= w_log, "region exceeds walk domain");
    assert_eq!(base % slots, 0, "dyadic region alignment");
    assert!(
        base + slots <= 1usize << w_log,
        "region outside walk domain"
    );
    (region_log..w_log)
        .map(|bit| (base >> bit) & 1 == 1)
        .collect()
}

/// Restrict a periodic fixed pattern to one aligned dyadic sub-region.  When
/// the region spans the whole walk no gate is necessary (and `FixedPattern`
/// intentionally rejects an empty high gate).
pub(crate) fn pattern_in_dyadic_region(
    pattern: FixedPattern,
    base: usize,
    slots: usize,
    w_log: usize,
) -> FixedPattern {
    let bits = dyadic_region_bits(base, slots, w_log);
    if bits.is_empty() {
        assert_eq!(base, 0, "whole-domain region starts at zero");
        pattern
    } else {
        pattern.gated(slots.trailing_zeros() as usize, bits)
    }
}

#[cfg(test)]
mod split_walk_a_layout_tests {
    use super::*;

    fn production_split_b(k: usize) -> (TiledWalkLayout, TiledWalkLayout, TiledWalkLayout) {
        // Owner-auth capsule: nq=64, source/mid depths 5/6, both stride 8.
        let wallet_slots: [usize; 2] = [64 * 8, 64 * 8];
        // Current legacy B255 meta carrier: 12 depth-16 exact-state paths and
        // one depth-8 universal tx-root path per authorization tile.
        let meta_slots: [usize; 2] = [
            12 * (2usize * 16).next_power_of_two(),
            (2usize * 8).next_power_of_two(),
        ];
        let wallet = tiled_walk_layout(k, &wallet_slots);
        let meta = tiled_walk_layout(k, &meta_slots);
        let combined = tiled_walk_layout(
            k,
            &[
                wallet_slots[0],
                wallet_slots[1],
                meta_slots[0],
                meta_slots[1],
            ],
        );
        (wallet, meta, combined)
    }

    #[test]
    fn split_walk_b_layout_and_k1_k2_matrix() {
        let (w1, m1, old1) = production_split_b(1);
        let (w2, m2, old2) = production_split_b(2);

        assert_eq!(w1.bases, vec![0, 512]);
        assert_eq!(
            (w1.live_per_block, w1.block_slots, w1.w_log),
            (1024, 1024, 10)
        );
        assert_eq!(m1.bases, vec![0, 384]);
        assert_eq!((m1.live_per_block, m1.block_slots, m1.w_log), (400, 512, 9));
        assert_eq!(
            (old1.live_per_block, old1.block_slots, old1.w_log),
            (1424, 2048, 11)
        );

        // K changes only the high tile axis: bases, block logs, and therefore
        // every common-period relation matrix stay identical; each walk gains
        // exactly one high variable/domain bit.
        assert_eq!(w2.bases, w1.bases);
        assert_eq!(m2.bases, m1.bases);
        assert_eq!(w2.block_log, w1.block_log);
        assert_eq!(m2.block_log, m1.block_log);
        assert_eq!(w2.w_log, w1.w_log + 1);
        assert_eq!(m2.w_log, m1.w_log + 1);
        assert_eq!(old2.w_log, old1.w_log + 1);
        assert_eq!(w2.slots, 2 * w1.slots);
        assert_eq!(m2.slots, 2 * m1.slots);

        let wallet_matrix_k1 = common_period_ones(0, 512, w1.block_log);
        let wallet_matrix_k2 = common_period_ones(0, 512, w2.block_log);
        let meta_matrix_k1 = common_period_ones(384, 16, m1.block_log);
        let meta_matrix_k2 = common_period_ones(384, 16, m2.block_log);
        assert_eq!(wallet_matrix_k1, wallet_matrix_k2, "wallet-B matrix period");
        assert_eq!(meta_matrix_k1, meta_matrix_k2, "meta-B matrix period");

        const COLS: usize = 9;
        assert_eq!(
            COLS * (old1.slots - w1.slots - m1.slots),
            4_608,
            "K=1 raw split saving"
        );
        assert_eq!(
            COLS * (old2.slots - w2.slots - m2.slots),
            9_216,
            "K=2 raw split saving"
        );
    }

    #[test]
    fn split_walk_b_b255_raw_saving_is_1_179_648_rows() {
        let (wallet, meta, old) = production_split_b(256);
        assert_eq!(wallet.slots, 262_144);
        assert_eq!(meta.slots, 131_072);
        assert_eq!(old.slots, 524_288);
        assert_eq!(9 * (old.slots - wallet.slots - meta.slots), 1_179_648);
    }

    #[test]
    fn packed_query_bits_fill_exact_live_and_tail_d_cells() {
        let ff_bases = [0, 512];
        let ff_strides = [8, 8];
        let ff_depths = [5, 6];
        let native_queries = [0b10_10101_0110011usize, 0b01_01010_1001100usize];
        let mut d = vec![F128::ZERO; 1024];
        fill_wallet_query_bit_carriers(
            &mut d,
            0,
            ff_bases,
            ff_strides,
            ff_depths,
            &native_queries,
            native_queries.len(),
            OWNER_AUTH_NUM_VARS,
        );

        for (query, &index) in native_queries.iter().enumerate() {
            for bit in 0..OWNER_AUTH_NUM_VARS + CAPSULE_LOG_RATE {
                let slot = wallet_query_bit_slot(
                    0,
                    ff_bases,
                    ff_strides,
                    ff_depths,
                    query,
                    bit,
                    OWNER_AUTH_NUM_VARS,
                );
                let expected = if (index >> bit) & 1 == 1 {
                    F128::ONE
                } else {
                    F128::ZERO
                };
                assert_eq!(d[slot], expected, "query {query} bit {bit}");
            }
            let duplicate = wallet_query_bit0_duplicate_slot(0, ff_bases, ff_strides, query);
            assert_eq!(d[duplicate], d[query * ff_strides[0]], "bit-0 copy");
        }

        // The exact carrier geometry consumes all three source tails and the
        // mid root-copy D cell, leaving only mid tail 7 canonical zero.
        for query in 0..native_queries.len() {
            assert_eq!(d[ff_bases[1] + query * ff_strides[1] + 7], F128::ZERO);
        }
    }

    #[test]
    fn ff_d_committed_slice_is_exact_boolean_at_no_extra_row_cost() {
        let column = (0..8)
            .map(|slot| if slot & 1 == 1 { F128::ONE } else { F128::ZERO })
            .collect::<Vec<_>>();
        let mut b = FieldR1csBuilder::new();
        let before = b.num_wires();
        let (slice, wires) = alloc_boolean_column_slice(&mut b, &column, 3);
        assert_eq!(wires.len(), column.len());
        assert_eq!(
            b.num_wires() - before,
            15,
            "seven alignment rows plus the same eight committed cells"
        );
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
        let mut bad = witness;
        bad[slice.start()] = F128::new(2, 0);
        assert!(
            !r1cs.satisfies(&bad),
            "non-boolean committed D cell survived exact allocation row"
        );
    }

    fn paired_meta_layout(
        k: usize,
        touched_capacity: usize,
        segment_capacity: usize,
        tx_root_slots: usize,
    ) -> TiledWalkLayout {
        tiled_walk_layout(
            k,
            &[
                touched_capacity.div_ceil(k) * PAIRED_UPDATE_STRIDE,
                segment_capacity.div_ceil(k) * PAIRED_UPDATE_STRIDE,
                tx_root_slots,
            ],
        )
    }

    #[test]
    fn paired_meta_b_shape_k1_k2_and_b255_m17() {
        // Same per-tile class matrix: doubling both fixed capacities and K
        // adds one high tile coordinate and leaves every low pattern intact.
        let k1 = paired_meta_layout(1, 6, 1, 16);
        let k2 = paired_meta_layout(2, 12, 2, 16);
        assert_eq!(k1.bases, vec![0, 384, 448]);
        assert_eq!(k2.bases, k1.bases);
        assert_eq!(k1.block_slots, 512);
        assert_eq!(k2.block_slots, 512);
        assert_eq!(k2.w_log, k1.w_log + 1);
        assert_eq!(k2.slots, 2 * k1.slots);

        let b255 = paired_meta_layout(256, 1_531, 256, 16);
        assert_eq!(b255.bases, vec![0, 384, 448]);
        assert_eq!(b255.live_per_block, 464);
        assert_eq!(b255.block_slots, 512);
        assert_eq!(b255.slots, 131_072);
        assert_eq!(b255.w_log, 17, "B255 paired meta-B is m17");
        assert_eq!(9 * b255.slots, 1_179_648, "exactly nine meta-B columns");
        let b255_overhang_updates =
            256 * 1_531usize.div_ceil(256) - 1_531 + 256 * 256usize.div_ceil(256) - 256;
        assert_eq!(b255_overhang_updates, 5);
        assert_eq!(
            9 * PAIRED_UPDATE_STRIDE * b255_overhang_updates,
            2_880,
            "B255 paired overhang exact-cell rows"
        );
    }

    fn paired_witness(seed: u64) -> super::super::paired_merkle_update::PairedMerkleUpdateWitness {
        let lane = |offset: u64| F128::new(seed + offset, seed.rotate_left(17) ^ offset);
        super::super::paired_merkle_update::PairedMerkleUpdateWitness {
            old_entry: [lane(1), lane(2)],
            new_entry: [lane(3), lane(4)],
            siblings: std::array::from_fn(|level| {
                [lane(10 + 2 * level as u64), lane(11 + 2 * level as u64)]
            }),
            directions: std::array::from_fn(|level| (seed as usize + level) & 1 == 1),
        }
    }

    #[test]
    fn merkle_postcommit_protocol_matches_legacy_paired_meta_b() {
        let w_log = 6;
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        let columns = build_paired_merkle_update_columns(&[paired_witness(0x51de)], iv, w_log);
        let committed_owned = vec![
            columns.c[0].clone(),
            columns.c[1].clone(),
            columns.c[2].clone(),
            columns.c[3].clone(),
            columns.e[0].clone(),
            columns.e[1].clone(),
            columns.sib[0].clone(),
            columns.sib[1].clone(),
            columns.d.clone(),
        ];
        let committed: Vec<&[F128]> = committed_owned.iter().map(Vec::as_slice).collect();
        let mut fixed = paired_merkle_update_fixed_patterns(iv);
        fixed.push(common_period_ones(0, PAIRED_UPDATE_STRIDE, w_log));
        let paired = [PairedMerkleSpec {
            refs: paired_merkle_update_refs(0, 0),
            region: 11,
        }];
        let domain = b"walk-b-postcommit-legacy-parity";
        let legacy = run_merkle_union_native_with_paired(
            &committed,
            &columns.s0,
            &columns.s_out,
            &fixed,
            &[0, 1, 2, 3],
            &[],
            &[],
            &paired,
            w_log,
            domain,
        );

        let families = [MerkleProtocolFamily::paired_update(0)];
        let mut prover = FsLaneChallenger::new(domain);
        let (proof, claims) = prove_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &committed,
            &columns.s0,
            &columns.s_out,
            &mut prover,
        );
        let mut verifier = FsLaneChallenger::new(domain);
        let replay = verify_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &proof,
            &mut verifier,
        )
        .expect("postcommit Walk-B replay");

        assert_eq!(claims, replay);
        assert_eq!(proof.zero, legacy.zero_proof);
        assert_eq!(proof.selection, legacy.sel_proof);
        assert_eq!(proof.walk, legacy.walk_proof);
        assert_eq!(proof.substitution, legacy.sub_proof);
        assert_eq!(
            proof.zero_shifts,
            legacy
                .zero_shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            proof.shifts,
            legacy
                .shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            claims
                .iter()
                .map(|claim| (claim.column, claim.point.clone(), claim.value))
                .collect::<Vec<_>>(),
            legacy.pending
        );
    }

    #[test]
    fn merkle_postcommit_protocol_matches_mixed_production_meta_b_order() {
        let w_log = 8;
        let block_log = 8;
        let domain = b"walk-b-postcommit-mixed-meta-parity";
        let paired_iv = iv_flat_of_tag(TAG_EXSTNOD);
        let merkle_iv = iv_flat_of_tag(TAG_EXSTNOD);
        let (ghost_s0, ghost_out) =
            noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
        let mut committed_owned: Vec<Vec<F128>> =
            (0..9).map(|_| vec![F128::ZERO; 1usize << w_log]).collect();
        let mut s0: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; 1usize << w_log]);
        let mut s_out: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; 1usize << w_log]);
        for slot in 0..1usize << w_log {
            for lane in 0..STATE_SIZE {
                committed_owned[lane][slot] = ghost_out[lane];
                s0[lane][slot] = ghost_s0[lane];
                s_out[lane][slot] = ghost_out[lane];
            }
        }

        for (family, offset) in [paired_witness(0x6100), paired_witness(0x7200)]
            .into_iter()
            .zip([0usize, PAIRED_UPDATE_STRIDE])
        {
            let columns = build_paired_merkle_update_columns(&[family], paired_iv, 6);
            place_paired_merkle_updates(
                &mut committed_owned,
                &mut s0,
                &mut s_out,
                &columns,
                offset,
                PAIRED_UPDATE_STRIDE,
            );
        }

        let merkle_family = MerklePathFamily {
            depth: 2,
            n_paths: 1,
        };
        let merkle_columns = build_merkle_path_columns(
            &merkle_family,
            merkle_iv,
            &[MerklePathWitness {
                entry: [F128::new(7, 11), F128::new(13, 17)],
                siblings: vec![
                    [F128::new(19, 23), F128::new(29, 31)],
                    [F128::new(37, 41), F128::new(43, 47)],
                ],
                directions: vec![false, true],
            }],
            2,
        );
        place_merkle(
            &mut committed_owned,
            &mut s0,
            &mut s_out,
            &merkle_columns,
            4,
            2 * PAIRED_UPDATE_STRIDE,
            merkle_family.n_slots(),
        );

        let mut fixed = Vec::new();
        let mut paired_specs = Vec::new();
        for offset in [0usize, PAIRED_UPDATE_STRIDE] {
            let fixed_base = fixed.len();
            for pattern in paired_merkle_update_fixed_patterns(paired_iv) {
                fixed.push(common_period_pattern(&pattern.table, offset, 1, block_log));
            }
            fixed.push(common_period_ones(offset, PAIRED_UPDATE_STRIDE, block_log));
            paired_specs.push(PairedMerkleSpec {
                refs: paired_merkle_update_refs(0, fixed_base),
                region: fixed_base + 11,
            });
        }
        let merkle_fixed_base = fixed.len();
        for pattern in merkle_fixed_patterns(&merkle_family, merkle_iv) {
            fixed.push(common_period_pattern(
                &pattern.table,
                2 * PAIRED_UPDATE_STRIDE,
                merkle_family.n_paths,
                block_log,
            ));
        }
        fixed.push(common_period_ones(
            2 * PAIRED_UPDATE_STRIDE,
            merkle_family.n_slots(),
            block_log,
        ));
        let legs = [MerkleLeg {
            family: merkle_family,
            refs: union_merkle_refs(merkle_fixed_base),
            region: merkle_fixed_base + 8,
            committed_roots: Vec::new(),
            entry_wires: Vec::new(),
            root_wires: Vec::new(),
            path_slots: Vec::new(),
            recomputed_roots: Vec::new(),
        }];
        let committed: Vec<&[F128]> = committed_owned.iter().map(Vec::as_slice).collect();
        let legacy = run_merkle_union_native_with_paired(
            &committed,
            &s0,
            &s_out,
            &fixed,
            &[0, 1, 2, 3],
            &[],
            &legs,
            &paired_specs,
            w_log,
            domain,
        );

        let families = [
            MerkleProtocolFamily::paired_update(0),
            MerkleProtocolFamily::paired_update(12),
            MerkleProtocolFamily::two_permutation(merkle_fixed_base),
        ];
        let mut prover = FsLaneChallenger::new(domain);
        let (proof, claims) = prove_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &committed,
            &s0,
            &s_out,
            &mut prover,
        );
        let prover_next = prover.sample_f128();
        let mut verifier = FsLaneChallenger::new(domain);
        let replay = verify_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &proof,
            &mut verifier,
        )
        .expect("mixed meta-B replay");
        let verifier_next = verifier.sample_f128();

        assert_eq!(claims, replay);
        assert_eq!(prover_next, verifier_next, "postcommit transcript lockstep");
        assert_eq!(proof.zero, legacy.zero_proof);
        assert_eq!(proof.selection, legacy.sel_proof);
        assert_eq!(proof.walk, legacy.walk_proof);
        assert_eq!(proof.substitution, legacy.sub_proof);
        assert_eq!(
            proof.zero_shifts,
            legacy
                .zero_shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            proof.shifts,
            legacy
                .shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            claims
                .iter()
                .map(|claim| (claim.column, claim.point.clone(), claim.value))
                .collect::<Vec<_>>(),
            legacy.pending
        );
    }

    #[test]
    fn merkle_postcommit_protocol_matches_legacy_wallet_ff_b() {
        let w_log = 2;
        let domain = b"walk-b-postcommit-wallet-ff-parity";
        let iv = iv_flat_of_tag(noid_poseidon2b::native::domain::TAG_CAPSNODE);
        let family = FfMerklePathFamily {
            depth: 3,
            n_paths: 1,
        };
        let columns = build_ff_merkle_path_columns(
            &family,
            iv,
            &[FfMerklePathWitness {
                entry: [F128::new(5, 7), F128::new(11, 13)],
                siblings: vec![
                    [F128::new(17, 19), F128::new(23, 29)],
                    [F128::new(31, 37), F128::new(41, 43)],
                    [F128::new(47, 53), F128::new(59, 61)],
                ],
                directions: vec![false, true, false],
            }],
            w_log,
        );
        let committed_owned = vec![
            columns.c[0].clone(),
            columns.c[1].clone(),
            columns.c[2].clone(),
            columns.c[3].clone(),
            columns.cr[0].clone(),
            columns.cr[1].clone(),
            columns.sib[0].clone(),
            columns.sib[1].clone(),
            columns.d.clone(),
        ];
        let committed: Vec<&[F128]> = committed_owned.iter().map(Vec::as_slice).collect();
        let mut fixed = ff_merkle_fixed_patterns(&family, iv);
        fixed.push(common_period_ones(0, family.n_slots(), w_log));
        let ff = [FfLegSpec {
            refs: FfMerkleFamilyRefs {
                cr: [4, 5],
                sib: [6, 7],
                d: 8,
                c: [0, 1, 2, 3],
                node: 0,
                nodens: 1,
                start: 2,
                iv: [3, 4],
            },
            region: 5,
        }];
        let legacy = run_merkle_union_native(
            &committed,
            &columns.s0,
            &columns.s_out,
            &fixed,
            &[0, 1, 2, 3],
            &ff,
            &[],
            w_log,
            domain,
        );

        let families = [MerkleProtocolFamily::feed_forward(0)];
        let mut prover = FsLaneChallenger::new(domain);
        let (proof, claims) = prove_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &committed,
            &columns.s0,
            &columns.s_out,
            &mut prover,
        );
        let mut verifier = FsLaneChallenger::new(domain);
        let replay = verify_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &proof,
            &mut verifier,
        )
        .expect("wallet ff-B replay");

        assert_eq!(claims, replay);
        assert_eq!(proof.zero, legacy.zero_proof);
        assert_eq!(proof.selection, legacy.sel_proof);
        assert_eq!(proof.walk, legacy.walk_proof);
        assert_eq!(proof.substitution, legacy.sub_proof);
        assert_eq!(
            proof.zero_shifts,
            legacy
                .zero_shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            proof.shifts,
            legacy
                .shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            claims
                .iter()
                .map(|claim| (claim.column, claim.point.clone(), claim.value))
                .collect::<Vec<_>>(),
            legacy.pending
        );
    }

    #[test]
    fn paired_k2_overhang_is_canonical_and_stays_outside_handoff() {
        let k = 2usize;
        let class_capacities = [3usize, 1usize];
        let caps_per_block = [2usize, 1usize];
        let family_slots = caps_per_block.map(|cap| cap * PAIRED_UPDATE_STRIDE);
        let layout = tiled_walk_layout(k, &family_slots);
        assert_eq!(layout.bases, vec![0, 2 * PAIRED_UPDATE_STRIDE]);
        assert_eq!(layout.block_slots, 4 * PAIRED_UPDATE_STRIDE);

        let local_updates: Vec<_> = (0..class_capacities[0])
            .map(|i| paired_witness(0x3100 + i as u64))
            .collect();
        let upper_updates: Vec<_> = (0..class_capacities[1])
            .map(|i| paired_witness(0x4100 + i as u64))
            .collect();
        let partitions = [local_updates.as_slice(), upper_updates.as_slice()];
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        let mut cb: Vec<Vec<F128>> = (0..9).map(|_| vec![F128::ZERO; layout.slots]).collect();
        let mut s0: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; layout.slots]);
        let mut sout: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; layout.slots]);
        for block in 0..k {
            for family in 0..2 {
                let cap = caps_per_block[family];
                let lo = (block * cap).min(partitions[family].len());
                let hi = ((block + 1) * cap).min(partitions[family].len());
                let slots = cap * PAIRED_UPDATE_STRIDE;
                let columns = build_paired_merkle_update_columns(
                    &partitions[family][lo..hi],
                    iv,
                    slots.trailing_zeros() as usize,
                );
                place_paired_merkle_updates(
                    &mut cb,
                    &mut s0,
                    &mut sout,
                    &columns,
                    block * layout.block_slots + layout.bases[family],
                    slots,
                );
            }
        }

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = cb
            .iter()
            .map(|column| alloc_column_slice(&mut b, column, layout.w_log).0)
            .collect();
        let before_copies = b.num_wires();
        pin_paired_consistency_cells(
            &mut b,
            &slices,
            &layout,
            [layout.bases[0], layout.bases[1]],
            caps_per_block,
        );
        assert_eq!(
            b.num_wires() - before_copies,
            110 * 6,
            "exact copies cover all four local/upper tiles"
        );
        let before_ghosts = b.num_wires();
        pin_paired_overhang_ghost_cells(
            &mut b,
            &slices,
            &layout,
            [layout.bases[0], layout.bases[1]],
            caps_per_block,
            class_capacities,
            iv,
        );
        assert_eq!(
            b.num_wires() - before_ghosts,
            2 * 9 * PAIRED_UPDATE_STRIDE,
            "one local plus one upper overhang, 576 rows each"
        );

        let paired = ExactStatePairedRegionData {
            local_updates,
            upper_updates,
            local_update_count: class_capacities[0],
            upper_update_count: class_capacities[1],
            touched_capacity: class_capacities[0],
            segment_capacity: class_capacities[1],
            active_upper_depth: 16,
        };
        let handoff = paired_exact_state_cells(
            &slices,
            &layout,
            [layout.bases[0], layout.bases[1]],
            caps_per_block,
            &paired,
        );
        assert_eq!(handoff.local.len(), class_capacities[0]);
        assert_eq!(handoff.upper.len(), class_capacities[1]);

        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));

        // The last real local update is the exact prefix boundary: changing
        // its unconstrained entry is allowed by these copy/ghost pins, proving
        // the overhang range starts at (and not before) class capacity.
        let last_live = paired_update_base(
            &layout,
            layout.bases[0],
            caps_per_block[0],
            class_capacities[0] - 1,
        );
        let mut changed_live_boundary = witness.clone();
        changed_live_boundary[slices[4].start() + last_live] += F128::ONE;
        assert!(
            r1cs.satisfies(&changed_live_boundary),
            "last live update was accidentally ghost-pinned"
        );

        let local_ghost = paired_update_base(
            &layout,
            layout.bases[0],
            caps_per_block[0],
            class_capacities[0],
        );
        // Pick cells not covered by the copy constraints, so rejection comes
        // specifically from the canonical-ghost pins in every committed col.
        let ghost_probe_offsets = [0usize, 0, 0, 0, 0, 0, 1, 1, 1];
        for column in 0..9 {
            let mut bad = witness.clone();
            bad[slices[column].start() + local_ghost + ghost_probe_offsets[column]] += F128::ONE;
            assert!(
                !r1cs.satisfies(&bad),
                "local overhang mutation accepted in committed column {column}"
            );
        }

        let upper_ghost = paired_update_base(
            &layout,
            layout.bases[1],
            caps_per_block[1],
            class_capacities[1],
        );
        let mut bad_upper = witness.clone();
        bad_upper[slices[4].start() + upper_ghost] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad_upper),
            "upper overhang mutation accepted"
        );

        // Mutating a real new-even D without its old-even source exercises the
        // exact D-copy constraint at the K-tile boundary.
        let mut bad_d_copy = witness;
        bad_d_copy[slices[8].start() + last_live + 2] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad_d_copy),
            "paired D copy mutation accepted"
        );
    }

    #[test]
    fn paired_handoff_roots_depth8_depth16_and_copy_negative() {
        let local_update = paired_witness(0x1100);
        let upper_update = paired_witness(0x2200);
        let paired = ExactStatePairedRegionData {
            local_updates: vec![local_update.clone()],
            upper_updates: vec![upper_update.clone()],
            local_update_count: 1,
            upper_update_count: 1,
            touched_capacity: 1,
            segment_capacity: 1,
            active_upper_depth: 8,
        };
        let layout = tiled_walk_layout(1, &[PAIRED_UPDATE_STRIDE, PAIRED_UPDATE_STRIDE]);
        assert_eq!(layout.bases, vec![0, PAIRED_UPDATE_STRIDE]);
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        let local_cols = build_paired_merkle_update_columns(&[local_update], iv, 6);
        let upper_cols = build_paired_merkle_update_columns(&[upper_update], iv, 6);
        let mut cb: Vec<Vec<F128>> = (0..9).map(|_| vec![F128::ZERO; layout.slots]).collect();
        let mut s0: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; layout.slots]);
        let mut sout: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; layout.slots]);
        place_paired_merkle_updates(
            &mut cb,
            &mut s0,
            &mut sout,
            &local_cols,
            layout.bases[0],
            PAIRED_UPDATE_STRIDE,
        );
        place_paired_merkle_updates(
            &mut cb,
            &mut s0,
            &mut sout,
            &upper_cols,
            layout.bases[1],
            PAIRED_UPDATE_STRIDE,
        );

        let mut fixed = Vec::new();
        let mut specs = Vec::new();
        for family in 0..2 {
            let fixed_base = fixed.len();
            for pattern in paired_merkle_update_fixed_patterns(iv) {
                fixed.push(common_period_pattern(
                    &pattern.table,
                    layout.bases[family],
                    1,
                    layout.block_log,
                ));
            }
            fixed.push(common_period_ones(
                layout.bases[family],
                PAIRED_UPDATE_STRIDE,
                layout.block_log,
            ));
            specs.push(PairedMerkleSpec {
                refs: paired_merkle_update_refs(0, fixed_base),
                region: fixed_base + 11,
            });
        }
        let committed: Vec<&[F128]> = cb.iter().map(Vec::as_slice).collect();
        let native = run_merkle_union_native_with_paired(
            &committed,
            &s0,
            &sout,
            &fixed,
            &[0, 1, 2, 3],
            &[],
            &[],
            &specs,
            layout.w_log,
            b"paired-meta-native-test",
        );
        assert!(!native.pending.is_empty(), "paired native union claims");

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = cb
            .iter()
            .map(|column| alloc_column_slice(&mut b, column, layout.w_log).0)
            .collect();
        let mut channel = FsChannelTrace::new(&mut b, b"paired-meta-native-test");
        let (claims, leg_pins) = discharge_merkle_union_with_paired(
            &mut b,
            &mut channel,
            &fixed,
            &[0, 1, 2, 3],
            &[],
            &[],
            &specs,
            layout.w_log,
            &native,
        );
        assert!(!claims.is_empty(), "paired trace union claims");
        assert!(leg_pins.is_empty(), "paired family has no legacy leg pins");
        let before = b.num_wires();
        pin_paired_consistency_cells(&mut b, &slices, &layout, [0, 64], [1, 1]);
        assert_eq!(b.num_wires() - before, 220, "110 exact copies per update");
        let handoff = paired_exact_state_cells(&slices, &layout, [0, 64], [1, 1], &paired);
        assert_eq!(handoff.local.len(), 1);
        assert_eq!(handoff.upper.len(), 1);

        let local16 = local_cols.update_roots_at_depth(0, 16);
        let upper8 = upper_cols.update_roots_at_depth(0, 8);
        let upper16 = upper_cols.update_roots_at_depth(0, 16);
        for lane in 0..2 {
            assert_eq!(
                handoff.local[0].old_root[lane].eval(b.values()),
                local16.0[lane]
            );
            assert_eq!(
                handoff.local[0].new_root[lane].eval(b.values()),
                local16.1[lane]
            );
            assert_eq!(
                handoff.upper[0].old_roots[7][lane].eval(b.values()),
                upper8.0[lane]
            );
            assert_eq!(
                handoff.upper[0].new_roots[7][lane].eval(b.values()),
                upper8.1[lane]
            );
            assert_eq!(
                handoff.upper[0].old_roots[15][lane].eval(b.values()),
                upper16.0[lane]
            );
            assert_eq!(
                handoff.upper[0].new_roots[15][lane].eval(b.values()),
                upper16.1[lane]
            );
        }

        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
        let mut bad = witness.clone();
        // Upper update level 0: mutate new-even SIB0, which must equal the
        // old-even SIB0 exactly (no Fiat-Shamir mixing).
        bad[slices[6].start() + PAIRED_UPDATE_STRIDE + 2] += F128::ONE;
        assert!(!r1cs.satisfies(&bad), "paired SIB copy mutation accepted");
        let mut bad_bridge = witness;
        bad_bridge[slices[4].start() + 3] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad_bridge),
            "paired E bridge mutation accepted"
        );
    }

    #[test]
    fn legacy_vec_wrapper_preserves_claim_order_and_values() {
        let claim = |index: usize, value: u64| RegionPcsClaim {
            slice: WitnessSlice { log2_len: 3, index },
            point: vec![LinExpr::constant(F128::new(value, 0))],
            value: LinExpr::constant(F128::new(value + 1, 0)),
            native_point: vec![F128::new(value, 0)],
            native_value: F128::new(value + 1, 0),
        };
        let claims = legacy_region_claims(AuthPcsRegionDischarge {
            claims: vec![claim(2, 10), claim(4, 20)],
            paired: Some(PairedExactStateCells {
                local: Vec::new(),
                upper: Vec::new(),
            }),
        });
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].slice.index, 2);
        assert_eq!(claims[1].slice.index, 4);
        assert_eq!(claims[0].native_value, F128::new(11, 0));
        assert_eq!(claims[1].native_value, F128::new(21, 0));
    }

    #[test]
    fn direct_wallet_query_cells_cost_exactly_four_rows_and_bind_digest() {
        let mut b = FieldR1csBuilder::new();
        let zeros = vec![F128::ZERO; 32];
        let wallet: Vec<WitnessSlice> = (0..N_WALLET_COMMITTED)
            .map(|_| alloc_column_slice(&mut b, &zeros, 5).0)
            .collect();
        let walk_b: Vec<WitnessSlice> = (0..9)
            .map(|_| alloc_column_slice(&mut b, &zeros, 5).0)
            .collect();

        let before_symbols = b.num_wires();
        let symbols = capsule_symbol_cells(&wallet, 0);
        assert_eq!(symbols.len(), CAPSULE_LEAF_SYMBOLS);
        assert_eq!(
            b.num_wires(),
            before_symbols,
            "direct symbol reads allocate no rows"
        );

        pin_capsule_digest_bridges(&mut b, &wallet, &walk_b, [0, 16], [0, 16]);
        assert_eq!(
            b.num_wires() - before_symbols,
            4,
            "two digest lanes for each of source+mid"
        );
        let digest_cell = wallet[WALLET_C0].start() + CAPSULE_LEAF_DIGEST_SLOT;
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
        let mut bad = witness.clone();
        bad[digest_cell] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad),
            "direct digest bridge accepted tamper"
        );
    }

    #[test]
    fn b255_meta_gates_select_disjoint_dyadic_regions() {
        let w_log = 15usize;
        let es = pattern_in_dyadic_region(FixedPattern::new(0, vec![F128::ONE]), 0, 8192, w_log)
            .materialize(1usize << w_log);
        let spine = pattern_in_dyadic_region(
            FixedPattern::new(6, vec![F128::ONE; 64]),
            16384,
            16384,
            w_log,
        )
        .materialize(1usize << w_log);

        assert!(es[..8192].iter().all(|&v| v == F128::ONE));
        assert!(es[8192..].iter().all(|&v| v == F128::ZERO));
        assert!(spine[..16384].iter().all(|&v| v == F128::ZERO));
        assert!(spine[16384..].iter().all(|&v| v == F128::ONE));
    }

    #[test]
    fn b255_spine_exposure_repoint_includes_meta_region_bit() {
        let spec = SpineUnionSpec {
            tree_refs: SourceTreeRefs {
                code: [2, 3],
                kid: [0, 1],
                c: [4, 5, 6, 7],
                even_int: 0,
                odd_int: 1,
                leafodd: 2,
                iv: [3, 4],
            },
            wrap_refs: SpongeLeafRefs {
                in_: [2, 3],
                c: [4, 5, 6, 7],
                odd: 6,
                iv: [7, 8],
            },
            wrap_region: 5,
            kid_meta: [0, 1],
            c_meta: [4, 5],
            cap_log: 0,
            tx_log: 8,
            tree_base: 0,
            block_log_a: 6,
            walk_high_bits: vec![F128::ONE],
        };
        let expo_point: Vec<F128> = (0..spec.expo_wlog())
            .map(|i| F128 {
                lo: (i + 2) as u64,
                hi: 0,
            })
            .collect();
        let kid = spec.repoint_kid(&expo_point);
        let c = spec.repoint_c(&expo_point);

        assert_eq!(kid.len(), 15);
        assert_eq!(c.len(), 15);
        assert_eq!(kid[4], F128::ZERO, "KID low-half coordinate");
        assert_eq!(c[0], F128::ONE, "C odd-window coordinate");
        assert_eq!(kid[5], F128::ZERO, "tree half of compact tx block");
        assert_eq!(c[5], F128::ZERO, "tree half of compact tx block");
        assert_eq!(kid[14], F128::ONE, "upper block-meta region");
        assert_eq!(c[14], F128::ONE, "upper block-meta region");
    }
}

fn flat_mds_entry(e: usize, j: usize) -> F128 {
    noid_ivc_core::deep_chain::flat_mds(true)[e][j]
}

/// `arr[idx]` selected by the witness bits of `idx` (LSB first).
///
/// A highest-variable multilinear fold computes the same
/// `Σ_c eq(bits, c)·arr[c]` value in `N - 1` multiplications.  Building the
/// equality tensor and multiplying every table cell separately costs
/// `2N - 1`; the direct fold also retains class-fixed matrix columns because
/// every level reads both halves before applying its witness bit.
/// `arr.len()` must equal `2^bits.len()`.
fn select_by_bits(b: &mut FieldR1csBuilder, bits: &[LinExpr], arr: &[LinExpr]) -> LinExpr {
    debug_assert_eq!(arr.len(), 1usize << bits.len(), "select_by_bits arity");
    mle_evaluate_small_trace(b, arr, bits)
}

#[cfg(test)]
mod fold_selection_tests {
    use super::*;

    #[test]
    fn direct_bit_selection_is_exact_and_uses_n_minus_one_rows() {
        let values = (0..8)
            .map(|i| F128 {
                lo: 0xA500 + i,
                hi: 0x5A00 ^ i,
            })
            .collect::<Vec<_>>();
        for index in 0..values.len() {
            let mut b = FieldR1csBuilder::new();
            let table = values
                .iter()
                .map(|&value| LinExpr::from_wire(b.alloc_f128(value)))
                .collect::<Vec<_>>();
            let bits = (0..3)
                .map(|bit| LinExpr::from_wire(b.alloc_bool((index >> bit) & 1 == 1)))
                .collect::<Vec<_>>();
            let before = b.num_wires();
            let selected = select_by_bits(&mut b, &bits, &table);
            assert_eq!(b.num_wires() - before, values.len() - 1);
            assert_eq!(selected.eval(b.values()), values[index]);
            pin_eq(&mut b, &selected, &LinExpr::constant(values[index]));
            let (r1cs, witness) = b.build();
            assert!(r1cs.satisfies(&witness));
        }
    }

    #[test]
    fn closed_rate2_code_selection_matches_full_capsule_encoding() {
        let h_values = [
            F128 {
                lo: 0x0123_4567_89AB_CDEF,
                hi: 0x0FED_CBA9_7654_3210,
            },
            F128 {
                lo: 0xA55A_A55A_1234_5678,
                hi: 0x5AA5_5AA5_8765_4321,
            },
        ];
        for coset in 0..CAPSULE_RATE {
            for local in 0..2usize {
                let mut b = FieldR1csBuilder::new();
                let h = h_values
                    .iter()
                    .map(|&value| LinExpr::from_wire(b.alloc_f128(value)))
                    .collect::<Vec<_>>();
                let local_bit = LinExpr::from_wire(b.alloc_bool(local == 1));
                let rc_bits = (0..CAPSULE_LOG_RATE)
                    .map(|bit| LinExpr::from_wire(b.alloc_bool((coset >> bit) & 1 == 1)))
                    .collect::<Vec<_>>();
                let rc_tensor = bit_eq_tensor(&mut b, &rc_bits);
                let leaf_bits = std::iter::once(local_bit)
                    .chain(rc_bits.iter().cloned())
                    .collect::<Vec<_>>();

                let before = b.num_wires();
                let selected = select_rate2_capsule_code(&mut b, &h, &leaf_bits, &rc_tensor);
                assert_eq!(b.num_wires() - before, 2, "closed-form row count");

                let full = capsule_encode_trace(&h);
                let reference = select_by_bits(&mut b, &leaf_bits, &full);
                assert_eq!(selected.eval(b.values()), reference.eval(b.values()));
                pin_eq(&mut b, &selected, &reference);
                let (r1cs, witness) = b.build();
                assert!(r1cs.satisfies(&witness));
            }
        }
    }
}

/// Trace α-power MDS weights `m[j] = Σ_e α^{e+1}·flat(MDS[e][j])`.
pub(crate) fn mds_alpha_weights(
    b: &mut FieldR1csBuilder,
    alpha: &LinExpr,
) -> (Vec<LinExpr>, Vec<LinExpr>) {
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
/// shape (own patterns, zero LEAFODD), the one-slot wrap the region-gated
/// sponge shape, and the gated tiled exposure re-points into walk A through
/// the class-constant layout below.
#[derive(Clone, Debug)]
pub(crate) struct SpineUnionSpec {
    pub(crate) tree_refs: SourceTreeRefs,
    pub(crate) wrap_refs: SpongeLeafRefs,
    pub(crate) wrap_region: usize,
    /// Walk-A columns the 4 exposure claims re-point into.
    pub(crate) kid_meta: [usize; 2],
    pub(crate) c_meta: [usize; 2],
    /// `log2` of the per-block instance capacity / the tx count.
    pub(crate) cap_log: usize,
    pub(crate) tx_log: usize,
    /// In-block offset of instance 0's tree (a multiple of
    /// `SPINE_TREE_SLOTS << cap_log`).
    pub(crate) tree_base: usize,
    pub(crate) block_log_a: usize,
    /// Constant coordinates above the compact spine region, selecting its
    /// aligned slot inside the larger block-meta walk.
    pub(crate) walk_high_bits: Vec<F128>,
}

impl SpineUnionSpec {
    pub(crate) fn local_log(&self) -> usize {
        (SPINE_TREE_SLOTS / 2).trailing_zeros() as usize
    }
    pub(crate) fn expo_wlog(&self) -> usize {
        self.local_log() + self.cap_log + self.tx_log
    }
    /// The constant high in-block bits selecting the spine-tree run:
    /// `tree_base >> (log2(SPINE_TREE_SLOTS) + cap_log)`, emitted LSB-first
    /// up to `block_log_a`.
    pub(crate) fn base_bits(&self) -> Vec<F128> {
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
    pub(crate) fn repoint_kid(&self, expo_point: &[F128]) -> Vec<F128> {
        let (rho_local, rest) = expo_point.split_at(self.local_log());
        let (rho_i, rho_tx) = rest.split_at(self.cap_log);
        let mut pt = rho_local.to_vec();
        pt.push(F128::ZERO);
        pt.extend_from_slice(rho_i);
        pt.extend(self.base_bits());
        pt.extend_from_slice(rho_tx);
        pt.extend_from_slice(&self.walk_high_bits);
        pt
    }
    /// Re-point a C window claim: `[1, rho_local, rho_i, base bits, rho_tx]`.
    pub(crate) fn repoint_c(&self, expo_point: &[F128]) -> Vec<F128> {
        let (rho_local, rest) = expo_point.split_at(self.local_log());
        let (rho_i, rho_tx) = rest.split_at(self.cap_log);
        let mut pt = vec![F128::ONE];
        pt.extend_from_slice(rho_local);
        pt.extend_from_slice(rho_i);
        pt.extend(self.base_bits());
        pt.extend_from_slice(rho_tx);
        pt.extend_from_slice(&self.walk_high_bits);
        pt
    }
    /// The internal-child gate over the tiled exposure domain.
    pub(crate) fn gate_pattern(&self) -> FixedPattern {
        spine_tree_internal_child_pattern()
    }
}

pub(crate) struct UnionNative {
    pub(crate) sel_proof: ColumnRelationProof,
    pub(crate) walk_proof: DeepChainWalkProof,
    pub(crate) sub_proof: ColumnRelationProof,
    pub(crate) shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pub(crate) pending: Vec<(usize, Vec<F128>, F128)>,
    /// ONE gated tiled exposure over all spine trees + its 4 re-pointed
    /// claims (present iff the spine families ride this union).
    pub(crate) spine_expo_proof: Option<ColumnRelationProof>,
    pub(crate) spine_expo_pending: Vec<(usize, Vec<F128>, F128)>,
}

/// Serializable proof authority for one Walk-A union.  Terminal opening
/// descriptors and shift metadata are intentionally absent: both are derived
/// from the verification-key relation structure during replay.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct WalkAUnionProof {
    pub(crate) selection: ColumnRelationProof,
    pub(crate) walk: DeepChainWalkProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
    pub(crate) spine_exposure: Option<ColumnRelationProof>,
}

/// Serializable Walk-A authority with the deep-chain walk deliberately
/// deferred to its enclosing protocol.  This is the proof object used when
/// several prefix claims are reduced by a caller-owned walk; unlike
/// [`WalkAUnionProof`], it contains no dummy or ignored walk field.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct WalkAUnionWalkDeferredProof {
    pub(crate) selection: ColumnRelationProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
    pub(crate) spine_exposure: Option<ColumnRelationProof>,
}

/// Borrowed view shared by the legacy single-walk wrapper and a genuinely
/// walk-deferred authority.  Keeping this view borrowed avoids cloning the
/// relation and shift proofs merely to enter the phased verifier.
#[derive(Clone, Copy)]
pub(crate) struct WalkAUnionWalkDeferredProofRef<'a> {
    pub(crate) selection: &'a ColumnRelationProof,
    pub(crate) substitution: &'a ColumnRelationProof,
    pub(crate) shifts: &'a [ShiftDischargeProof],
    pub(crate) spine_exposure: Option<&'a ColumnRelationProof>,
}

impl WalkAUnionProof {
    pub(crate) fn walk_deferred(&self) -> WalkAUnionWalkDeferredProofRef<'_> {
        WalkAUnionWalkDeferredProofRef {
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
            spine_exposure: self.spine_exposure.as_ref(),
        }
    }
}

impl WalkAUnionWalkDeferredProof {
    pub(crate) fn as_ref(&self) -> WalkAUnionWalkDeferredProofRef<'_> {
        WalkAUnionWalkDeferredProofRef {
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
            spine_exposure: self.spine_exposure.as_ref(),
        }
    }
}

/// Prover typestate after Walk-A's selection prefix and before the caller's
/// deep-chain walk.  The selection claims are retained privately so the
/// suffix cannot accidentally omit them from the terminal PCS claim set.
pub(crate) struct WalkAUnionProverWalkPrefix {
    selection: ColumnRelationProof,
    pending: Vec<WalkAColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl WalkAUnionProverWalkPrefix {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

/// Verifier typestate at the same transcript boundary as
/// [`WalkAUnionProverWalkPrefix`].
pub(crate) struct WalkAUnionVerifierWalkPrefix<'a> {
    proof: WalkAUnionWalkDeferredProofRef<'a>,
    pending: Vec<WalkAColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl WalkAUnionVerifierWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

/// Verifier-derived terminal opening on a Walk-A committed column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WalkAColumnClaim {
    pub(crate) column: usize,
    pub(crate) point: Vec<F128>,
    pub(crate) value: F128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalkAUnionVerifyError {
    Shape,
    Selection(RelationError),
    Walk(WalkError),
    Substitution(RelationError),
    Shift(RelationError),
    SpineExposure(RelationError),
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
    // Spine families: the tree is the SOURCE-TREE shape on shared CODE/KID/C
    // columns (LEAFODD ≡ 0); the TAG_TX8X2 wrap is a one-slot sponge shape.
    if let Some(sp) = spine {
        terms.extend(source_tree_substitution_terms(&sp.tree_refs, alpha));
        gated_sponge_native_terms(&sp.wrap_refs, sp.wrap_region, alpha, &mut terms);
    }
    terms
}

/// Prove Walk-A's transcript prefix through carry selection, stopping before
/// any deep-chain walk messages are observed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_walk_a_union_walk_prefix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    committed: &[&[F128]],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> WalkAUnionProverWalkPrefix {
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    assert!(s_out.iter().all(|column| column.len() == w));

    let mut pending = Vec::new();
    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(meta_c, beta);
    let rho = challenger.sample_f128_vec(w_log);
    let internal: Vec<&[F128]> = s_out.iter().map(Vec::as_slice).collect();
    let (selection, selection_point, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &selection_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        challenger,
    );
    let mut output_values = [F128::ZERO; STATE_SIZE];
    for (reference, value) in claimed_refs(&selection_terms)
        .iter()
        .zip(selection.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(WalkAColumnClaim {
                column: *column,
                point: selection_point.clone(),
                value: *value,
            }),
            ColRef::Internal(lane) => output_values[*lane] = *value,
            _ => unreachable!("Walk-A selection claim kind"),
        }
    }

    WalkAUnionProverWalkPrefix {
        selection,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    }
}

/// Finish Walk-A after a caller-owned deep-chain walk has reduced the prefix
/// group to `terminal`.  The returned authority contains only the prefix and
/// suffix messages; the caller owns serialization of the walk itself.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_walk_a_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    committed: &[&[F128]],
    spine_expo_cols: Option<&[&[F128]; 4]>,
    prefix: WalkAUnionProverWalkPrefix,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> (WalkAUnionWalkDeferredProof, Vec<WalkAColumnClaim>) {
    assert_eq!(
        spine.is_some(),
        spine_expo_cols.is_some(),
        "spine exposure columns"
    );
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    let WalkAUnionProverWalkPrefix {
        selection,
        mut pending,
        walk_group: _,
    } = prefix;

    let alpha = challenger.sample_f128();
    let substitution_terms = union_native_terms(leaf_refs, es_sponge, spine, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let (substitution, substitution_point, _) = prove_column_relation(
        target,
        &terminal.point,
        &substitution_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        challenger,
    );

    let mut shifts = Vec::new();
    for (reference, value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(substitution.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(WalkAColumnClaim {
                column: *column,
                point: substitution_point.clone(),
                value: *value,
            }),
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let (shift, point) = prove_shift_discharge_pow2(
                    committed[*column],
                    &substitution_point,
                    *value,
                    shift_log,
                    challenger,
                );
                pending.push(WalkAColumnClaim {
                    column: *column,
                    point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            _ => unreachable!("Walk-A substitution claim kind"),
        }
    }

    let spine_exposure = if let (Some(spec), Some(columns)) = (spine, spine_expo_cols) {
        let gamma = challenger.sample_f128();
        let terms = spine_tree_exposure_terms([0, 1], [2, 3], 0, gamma);
        let fixed = vec![spec.gate_pattern()];
        let rho = challenger.sample_f128_vec(spec.expo_wlog());
        let (proof, point, _) = prove_column_relation(
            F128::ZERO,
            &rho,
            &terms,
            &RelationColumns {
                committed: columns,
                internal: &[],
                fixed: &fixed,
            },
            challenger,
        );
        for (reference, value) in claimed_refs(&terms).iter().zip(proof.final_values.iter()) {
            match reference {
                ColRef::Committed(local_column) => pending.push(WalkAColumnClaim {
                    column: spec.kid_meta[*local_column],
                    point: spec.repoint_kid(&point),
                    value: *value,
                }),
                ColRef::Window { col, .. } => pending.push(WalkAColumnClaim {
                    column: spec.c_meta[*col - 2],
                    point: spec.repoint_c(&point),
                    value: *value,
                }),
                _ => unreachable!("Walk-A spine exposure claim kind"),
            }
        }
        Some(proof)
    } else {
        None
    };

    (
        WalkAUnionWalkDeferredProof {
            selection,
            substitution,
            shifts,
            spine_exposure,
        },
        pending,
    )
}

/// Verify Walk-A's selection prefix and expose exactly one caller-owned walk
/// group.  No walk proof is accepted by this phase.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_walk_a_union_walk_prefix_with_challenger<'a, Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    proof: WalkAUnionWalkDeferredProofRef<'a>,
    challenger: &mut Ch,
) -> Result<WalkAUnionVerifierWalkPrefix<'a>, WalkAUnionVerifyError> {
    let mut pending = Vec::new();
    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(meta_c, beta);
    let rho = challenger.sample_f128_vec(w_log);
    let selection_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &selection_terms,
        fixed,
        proof.selection,
        challenger,
    )
    .map_err(WalkAUnionVerifyError::Selection)?;
    let mut output_values = [F128::ZERO; STATE_SIZE];
    for (reference, value) in claimed_refs(&selection_terms)
        .iter()
        .zip(proof.selection.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(WalkAColumnClaim {
                column: *column,
                point: selection_point.clone(),
                value: *value,
            }),
            ColRef::Internal(lane) if *lane < STATE_SIZE => output_values[*lane] = *value,
            _ => return Err(WalkAUnionVerifyError::Shape),
        }
    }

    Ok(WalkAUnionVerifierWalkPrefix {
        proof,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    })
}

/// Verify the Walk-A suffix against the terminal claim returned by the
/// caller-owned walk and reconstruct every committed-column opening.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_walk_a_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    prefix: WalkAUnionVerifierWalkPrefix<'_>,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> Result<Vec<WalkAColumnClaim>, WalkAUnionVerifyError> {
    let WalkAUnionVerifierWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = challenger.sample_f128();
    let substitution_terms = union_native_terms(leaf_refs, es_sponge, spine, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let substitution_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &substitution_terms,
        fixed,
        proof.substitution,
        challenger,
    )
    .map_err(WalkAUnionVerifyError::Substitution)?;

    let mut shift_cursor = 0usize;
    for (reference, value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(proof.substitution.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(WalkAColumnClaim {
                column: *column,
                point: substitution_point.clone(),
                value: *value,
            }),
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let shift = proof
                    .shifts
                    .get(shift_cursor)
                    .ok_or(WalkAUnionVerifyError::Shape)?;
                shift_cursor += 1;
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let point = verify_shift_discharge_pow2(
                    w_log,
                    &substitution_point,
                    *value,
                    shift_log,
                    shift,
                    challenger,
                )
                .map_err(WalkAUnionVerifyError::Shift)?;
                pending.push(WalkAColumnClaim {
                    column: *column,
                    point,
                    value: shift.final_value,
                });
            }
            _ => return Err(WalkAUnionVerifyError::Shape),
        }
    }
    if shift_cursor != proof.shifts.len() {
        return Err(WalkAUnionVerifyError::Shape);
    }

    match (spine, proof.spine_exposure) {
        (None, None) => {}
        (Some(spec), Some(exposure)) => {
            let gamma = challenger.sample_f128();
            let terms = spine_tree_exposure_terms([0, 1], [2, 3], 0, gamma);
            let fixed = vec![spec.gate_pattern()];
            let rho = challenger.sample_f128_vec(spec.expo_wlog());
            let point = verify_column_relation(
                spec.expo_wlog(),
                F128::ZERO,
                &rho,
                &terms,
                &fixed,
                exposure,
                challenger,
            )
            .map_err(WalkAUnionVerifyError::SpineExposure)?;
            for (reference, value) in claimed_refs(&terms)
                .iter()
                .zip(exposure.final_values.iter())
            {
                match reference {
                    ColRef::Committed(local_column) if *local_column < 2 => {
                        pending.push(WalkAColumnClaim {
                            column: spec.kid_meta[*local_column],
                            point: spec.repoint_kid(&point),
                            value: *value,
                        });
                    }
                    ColRef::Window {
                        col,
                        stride_log: 1,
                        offset: 1,
                    } if (2..4).contains(col) => pending.push(WalkAColumnClaim {
                        column: spec.c_meta[*col - 2],
                        point: spec.repoint_c(&point),
                        value: *value,
                    }),
                    _ => return Err(WalkAUnionVerifyError::Shape),
                }
            }
        }
        _ => return Err(WalkAUnionVerifyError::Shape),
    }
    Ok(pending)
}

/// Prover half of the Walk-A protocol over an already-bound transcript.
///
/// The caller owns domain separation and MUST invoke this only after the
/// enclosing witness commitment has been absorbed.  No challenger is
/// constructed here.  The returned terminal claims are transient and are not
/// part of [`WalkAUnionProof`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_walk_a_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    spine_expo_cols: Option<&[&[F128]; 4]>,
    challenger: &mut Ch,
) -> (WalkAUnionProof, Vec<WalkAColumnClaim>) {
    let w = 1usize << w_log;
    assert!(s0.iter().all(|column| column.len() == w));
    let prefix = prove_walk_a_union_walk_prefix_with_challenger(
        w_log, fixed, meta_c, committed, s_out, challenger,
    );
    let groups = [prefix.walk_group().clone()];
    let (walk, terminal) = prove_deep_chain_walk(s0, &groups, challenger);
    let (deferred, pending) = prove_walk_a_union_walk_suffix_with_challenger(
        w_log,
        fixed,
        leaf_refs,
        es_sponge,
        spine,
        committed,
        spine_expo_cols,
        prefix,
        &terminal,
        challenger,
    );
    (
        WalkAUnionProof {
            selection: deferred.selection,
            walk,
            substitution: deferred.substitution,
            shifts: deferred.shifts,
            spine_exposure: deferred.spine_exposure,
        },
        pending,
    )
}

/// Verifier half of [`prove_walk_a_union_with_challenger`].  Every terminal
/// PCS descriptor is reconstructed from the fixed relation structure and the
/// verified endpoints; the proof supplies no column, point, or shift metadata.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_walk_a_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    proof: &WalkAUnionProof,
    challenger: &mut Ch,
) -> Result<Vec<WalkAColumnClaim>, WalkAUnionVerifyError> {
    let deferred = proof.walk_deferred();
    let prefix = verify_walk_a_union_walk_prefix_with_challenger(
        w_log, fixed, meta_c, deferred, challenger,
    )?;
    let groups = [prefix.walk_group().clone()];
    let terminal = verify_deep_chain_walk(w_log, &groups, &proof.walk, challenger)
        .map_err(WalkAUnionVerifyError::Walk)?;
    verify_walk_a_union_walk_suffix_with_challenger(
        w_log, fixed, leaf_refs, es_sponge, spine, prefix, &terminal, challenger,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_union_native(
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
    domain: &[u8],
) -> UnionNative {
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let (proof, prover_claims) = prove_walk_a_union_with_challenger(
        w_log,
        fixed,
        meta_c,
        leaf_refs,
        es_sponge,
        spine,
        committed,
        s0,
        s_out,
        spine_expo_cols,
        &mut ch_p,
    );
    let verifier_claims = verify_walk_a_union_with_challenger(
        w_log, fixed, meta_c, leaf_refs, es_sponge, spine, &proof, &mut ch_v,
    )
    .expect("native Walk-A union");
    assert_eq!(prover_claims, verifier_claims, "Walk-A terminal claims");
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native lockstep");

    let exposure_count = if spine.is_some() { 4 } else { 0 };
    let main_count = prover_claims
        .len()
        .checked_sub(exposure_count)
        .expect("Walk-A exposure claim count");
    let pending = prover_claims[..main_count]
        .iter()
        .map(|claim| (claim.column, claim.point.clone(), claim.value))
        .collect();
    let spine_expo_pending = prover_claims[main_count..]
        .iter()
        .map(|claim| (claim.column, claim.point.clone(), claim.value))
        .collect();

    let shift_layout: Vec<(usize, usize)> =
        claimed_refs(&union_native_terms(leaf_refs, es_sponge, spine, F128::ONE))
            .into_iter()
            .filter_map(|reference| match reference {
                ColRef::CommittedShift(column) => Some((0, column)),
                ColRef::CommittedShift2(column) => Some((1, column)),
                _ => None,
            })
            .collect();
    assert_eq!(shift_layout.len(), proof.shifts.len());
    let shifts = shift_layout
        .into_iter()
        .zip(proof.shifts.iter().cloned())
        .map(|((shift_log, column), shift)| (shift_log, column, shift))
        .collect();

    UnionNative {
        sel_proof: proof.selection,
        walk_proof: proof.walk,
        sub_proof: proof.substitution,
        shifts,
        pending,
        spine_expo_proof: proof.spine_exposure,
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
/// families, the exact-state sponge tiles and the one-slot spine wrap all
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
pub(crate) fn union_trace_terms(
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
        gated_sponge_trace_terms(m, &sp.wrap_refs, sp.wrap_region, &mut terms);
    }
    terms
}

pub(crate) fn union_ref_terms(
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
            for bit in &sp.walk_high_bits {
                pt.push(LinExpr::constant(*bit));
            }
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

/// One fixed-capacity paired-update family (local or upper) sharing meta-B's
/// nine committed columns. `region` gates the otherwise-unconditional ghost
/// carry base in the substitution relation.
#[derive(Clone, Copy)]
struct PairedMerkleSpec {
    refs: PairedMerkleUpdateRefs,
    region: usize,
}

/// The existing union zero-check: every 2-perm leg's direction booleanity,
/// plus every ff leg's two CR-chain lanes weighted by λ and λ². Feed-forward
/// D booleanity is deliberately NOT mixed into this relation: wallet-B's D
/// committed slice is allocated as exact boolean R1CS rows.
fn union_zero_terms(
    legs: &[MerkleLeg],
    ff_specs: &[FfLegSpec],
    paired_specs: &[PairedMerkleSpec],
    lambda: F128,
) -> Vec<RelationTerm> {
    let mut t = Vec::new();
    for leg in legs {
        t.extend(merkle_booleanity_terms(&leg.refs));
    }
    for spec in ff_specs {
        t.extend(ff_merkle_chain_terms(&spec.refs, lambda));
    }
    for spec in paired_specs {
        t.push(RelationTerm {
            coeff: F128::ONE,
            factors: vec![
                ColRef::Fixed(spec.refs.old_even),
                ColRef::Committed(spec.refs.d),
                ColRef::Committed(spec.refs.d),
            ],
        });
        t.push(RelationTerm {
            coeff: F128::ONE,
            factors: vec![
                ColRef::Fixed(spec.refs.old_even),
                ColRef::Committed(spec.refs.d),
            ],
        });
    }
    t
}

fn union_zero_terms_trace(
    b: &mut FieldR1csBuilder,
    legs: &[MerkleLeg],
    ff_specs: &[FfLegSpec],
    paired_specs: &[PairedMerkleSpec],
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
    for spec in paired_specs {
        for factors in [
            vec![
                ColRef::Fixed(spec.refs.old_even),
                ColRef::Committed(spec.refs.d),
                ColRef::Committed(spec.refs.d),
            ],
            vec![
                ColRef::Fixed(spec.refs.old_even),
                ColRef::Committed(spec.refs.d),
            ],
        ] {
            t.push(RelationTermTrace {
                coeff: LinExpr::constant(F128::ONE),
                factors,
            });
        }
    }
    t
}

fn union_sub_terms_native(
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    paired_specs: &[PairedMerkleSpec],
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
    for spec in paired_specs {
        let mut paired = paired_merkle_update_substitution_terms(&spec.refs, alpha);
        for term in &mut paired {
            if !term
                .factors
                .iter()
                .any(|factor| matches!(factor, ColRef::Fixed(_)))
            {
                term.factors.insert(0, ColRef::Fixed(spec.region));
            }
        }
        terms.extend(paired);
    }
    terms
}

/// Trace-coefficient twin of `paired_merkle_update_substitution_terms`.
/// Exact SIB/D copies and E bridges are intentionally absent here: they are
/// direct Stage-2 cell equalities, never challenge-mixed relation terms.
fn paired_substitution_terms_trace(
    m: &[LinExpr],
    spec: &PairedMerkleSpec,
) -> Vec<RelationTermTrace> {
    assert_eq!(m.len(), STATE_SIZE, "paired MDS weight count");
    let refs = &spec.refs;
    let mut terms = Vec::new();
    let mut push = |coeff: LinExpr, mut factors: Vec<ColRef>| {
        if !factors
            .iter()
            .any(|factor| matches!(factor, ColRef::Fixed(_)))
        {
            factors.insert(0, ColRef::Fixed(spec.region));
        }
        terms.push(RelationTermTrace { coeff, factors });
    };

    for lane in 0..2 {
        let c_shift = ColRef::CommittedShift(refs.c[lane]);
        let e = ColRef::Committed(refs.e[lane]);
        let e_shift = ColRef::CommittedShift(refs.e[lane]);
        let e_shift2 = ColRef::CommittedShift2(refs.e[lane]);
        let sib = ColRef::Committed(refs.sib[lane]);
        let sib_shift = ColRef::CommittedShift(refs.sib[lane]);
        let d = ColRef::Committed(refs.d);
        let d_shift = ColRef::CommittedShift(refs.d);
        for factors in [
            vec![c_shift],
            vec![ColRef::Fixed(refs.even), c_shift],
            vec![ColRef::Fixed(refs.even_start), e],
            vec![ColRef::Fixed(refs.even_start), d, e],
            vec![ColRef::Fixed(refs.even_nonstart), e_shift],
            vec![ColRef::Fixed(refs.even_nonstart), d, e_shift],
            vec![ColRef::Fixed(refs.even), d, sib],
            vec![ColRef::Fixed(refs.odd), sib_shift],
            vec![ColRef::Fixed(refs.odd), d_shift, sib_shift],
            vec![ColRef::Fixed(refs.odd_start), d_shift, e_shift],
            vec![ColRef::Fixed(refs.odd_nonstart), d_shift, e_shift2],
        ] {
            push(m[lane].clone(), factors);
        }
    }
    for lane in 2..STATE_SIZE {
        let c_shift = ColRef::CommittedShift(refs.c[lane]);
        for factors in [
            vec![c_shift],
            vec![ColRef::Fixed(refs.even), c_shift],
            vec![ColRef::Fixed(refs.iv[lane - 2])],
        ] {
            push(m[lane].clone(), factors);
        }
    }
    terms
}

fn union_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    paired_specs: &[PairedMerkleSpec],
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
    for spec in paired_specs {
        terms.extend(paired_substitution_terms_trace(&m, spec));
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

/// Canonical relation family inside the shared nine-column Walk-B table.
///
/// The committed-column map is fixed for every variant:
/// `C0..C3,E0,E1,SIB0,SIB1,D`.  Only fixed-pattern indices vary.  A region
/// sidecar constructs these values from its ordered family list; they are not
/// serialized as prover authority.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MerkleProtocolFamily {
    FeedForward {
        refs: FfMerkleFamilyRefs,
        region: usize,
    },
    TwoPermutation {
        refs: MerkleFamilyRefs,
        region: usize,
    },
    PairedUpdate {
        refs: PairedMerkleUpdateRefs,
        region: usize,
    },
}

impl MerkleProtocolFamily {
    pub(crate) fn feed_forward(fixed_base: usize) -> Self {
        Self::FeedForward {
            refs: FfMerkleFamilyRefs {
                cr: [4, 5],
                sib: [6, 7],
                d: 8,
                c: std::array::from_fn(|lane| lane),
                node: fixed_base,
                nodens: fixed_base + 1,
                start: fixed_base + 2,
                iv: [fixed_base + 3, fixed_base + 4],
            },
            region: fixed_base + 5,
        }
    }

    pub(crate) fn two_permutation(fixed_base: usize) -> Self {
        Self::TwoPermutation {
            refs: union_merkle_refs(fixed_base),
            region: fixed_base + 8,
        }
    }

    pub(crate) fn paired_update(fixed_base: usize) -> Self {
        Self::PairedUpdate {
            refs: paired_merkle_update_refs(0, fixed_base),
            region: fixed_base + 11,
        }
    }
}

/// Serializable Walk-B proof authority.  In particular this type contains no
/// `pending` opening list: terminal column descriptors are reconstructed from
/// the verifier's fixed family list while replaying the proof.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct MerkleUnionProof {
    pub(crate) zero: ColumnRelationProof,
    pub(crate) zero_shifts: Vec<ShiftDischargeProof>,
    pub(crate) selection: ColumnRelationProof,
    pub(crate) walk: DeepChainWalkProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
}

/// Serializable Walk-B authority whose deep-chain walk is owned by an
/// enclosing protocol.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct MerkleUnionWalkDeferredProof {
    pub(crate) zero: ColumnRelationProof,
    pub(crate) zero_shifts: Vec<ShiftDischargeProof>,
    pub(crate) selection: ColumnRelationProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
}

#[derive(Clone, Copy)]
pub(crate) struct MerkleUnionWalkDeferredProofRef<'a> {
    pub(crate) zero: &'a ColumnRelationProof,
    pub(crate) zero_shifts: &'a [ShiftDischargeProof],
    pub(crate) selection: &'a ColumnRelationProof,
    pub(crate) substitution: &'a ColumnRelationProof,
    pub(crate) shifts: &'a [ShiftDischargeProof],
}

impl MerkleUnionProof {
    pub(crate) fn walk_deferred(&self) -> MerkleUnionWalkDeferredProofRef<'_> {
        MerkleUnionWalkDeferredProofRef {
            zero: &self.zero,
            zero_shifts: &self.zero_shifts,
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
        }
    }
}

impl MerkleUnionWalkDeferredProof {
    pub(crate) fn as_ref(&self) -> MerkleUnionWalkDeferredProofRef<'_> {
        MerkleUnionWalkDeferredProofRef {
            zero: &self.zero,
            zero_shifts: &self.zero_shifts,
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
        }
    }
}

pub(crate) struct MerkleUnionProverWalkPrefix {
    zero: ColumnRelationProof,
    zero_shifts: Vec<ShiftDischargeProof>,
    selection: ColumnRelationProof,
    pending: Vec<MerkleColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl MerkleUnionProverWalkPrefix {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

pub(crate) struct MerkleUnionVerifierWalkPrefix<'a> {
    proof: MerkleUnionWalkDeferredProofRef<'a>,
    pending: Vec<MerkleColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl MerkleUnionVerifierWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

/// One verifier-derived terminal claim on a shared Walk-B column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MerkleColumnClaim {
    pub(crate) column: usize,
    pub(crate) point: Vec<F128>,
    pub(crate) value: F128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MerkleUnionVerifyError {
    Shape,
    Zero(RelationError),
    Selection(RelationError),
    Walk(WalkError),
    Substitution(RelationError),
    Shift(RelationError),
}

pub(crate) fn merkle_protocol_zero_terms(
    families: &[MerkleProtocolFamily],
    lambda: F128,
) -> Vec<RelationTerm> {
    let mut terms = Vec::new();
    // Transcript compatibility is category-ordered, independently of the
    // physical fixed-pattern group order.
    for family in families {
        if let MerkleProtocolFamily::TwoPermutation { refs, .. } = family {
            terms.extend(merkle_booleanity_terms(refs));
        }
    }
    for family in families {
        if let MerkleProtocolFamily::FeedForward { refs, .. } = family {
            terms.extend(ff_merkle_chain_terms(refs, lambda));
        }
    }
    for family in families {
        if let MerkleProtocolFamily::PairedUpdate { refs, .. } = family {
            terms.push(RelationTerm {
                coeff: F128::ONE,
                factors: vec![
                    ColRef::Fixed(refs.old_even),
                    ColRef::Committed(refs.d),
                    ColRef::Committed(refs.d),
                ],
            });
            terms.push(RelationTerm {
                coeff: F128::ONE,
                factors: vec![ColRef::Fixed(refs.old_even), ColRef::Committed(refs.d)],
            });
        }
    }
    terms
}

pub(crate) fn merkle_protocol_substitution_terms(
    families: &[MerkleProtocolFamily],
    alpha: F128,
) -> Vec<RelationTerm> {
    let m = mds_weights_pub(alpha);
    let mut terms = Vec::new();
    for family in families {
        if let MerkleProtocolFamily::FeedForward { refs, region } = family {
            for lane in 0..STATE_SIZE {
                terms.push(RelationTerm {
                    coeff: m[lane],
                    factors: vec![ColRef::Fixed(*region), ColRef::CommittedShift(refs.c[lane])],
                });
            }
            terms.extend(ff_merkle_substitution_terms(refs, alpha));
        }
    }
    for family in families {
        if let MerkleProtocolFamily::TwoPermutation { refs, region } = family {
            let mut family_terms = merkle_substitution_terms(refs, alpha);
            for term in &mut family_terms {
                if !term
                    .factors
                    .iter()
                    .any(|factor| matches!(factor, ColRef::Fixed(_)))
                {
                    term.factors.insert(0, ColRef::Fixed(*region));
                }
            }
            terms.extend(family_terms);
        }
    }
    for family in families {
        if let MerkleProtocolFamily::PairedUpdate { refs, region } = family {
            let mut family_terms = paired_merkle_update_substitution_terms(refs, alpha);
            for term in &mut family_terms {
                if !term
                    .factors
                    .iter()
                    .any(|factor| matches!(factor, ColRef::Fixed(_)))
                {
                    term.factors.insert(0, ColRef::Fixed(*region));
                }
            }
            terms.extend(family_terms);
        }
    }
    terms
}

fn prove_merkle_claim_pass<Ch: Challenger>(
    committed: &[&[F128]],
    references: &[ColRef],
    values: &[F128],
    point: &[F128],
    challenger: &mut Ch,
) -> (
    [F128; STATE_SIZE],
    Vec<MerkleColumnClaim>,
    Vec<ShiftDischargeProof>,
) {
    assert_eq!(references.len(), values.len(), "Walk-B claim shape");
    let mut internal = [F128::ZERO; STATE_SIZE];
    let mut pending = Vec::new();
    let mut shifts = Vec::new();
    for (reference, value) in references.iter().zip(values) {
        match reference {
            ColRef::Committed(column) => pending.push(MerkleColumnClaim {
                column: *column,
                point: point.to_vec(),
                value: *value,
            }),
            ColRef::Internal(lane) => internal[*lane] = *value,
            ColRef::CommittedShift(column) => {
                let (shift, shifted_point) =
                    prove_shift_discharge(committed[*column], point, *value, challenger);
                pending.push(MerkleColumnClaim {
                    column: *column,
                    point: shifted_point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            ColRef::CommittedShift2(column) => {
                let (shift, shifted_point) =
                    prove_shift_discharge_pow2(committed[*column], point, *value, 1, challenger);
                pending.push(MerkleColumnClaim {
                    column: *column,
                    point: shifted_point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            _ => unreachable!("Walk-B terminal claim kind"),
        }
    }
    (internal, pending, shifts)
}

fn verify_merkle_claim_pass<Ch: Challenger>(
    w_log: usize,
    references: &[ColRef],
    values: &[F128],
    point: &[F128],
    proof_shifts: &[ShiftDischargeProof],
    challenger: &mut Ch,
) -> Result<([F128; STATE_SIZE], Vec<MerkleColumnClaim>), MerkleUnionVerifyError> {
    if references.len() != values.len() {
        return Err(MerkleUnionVerifyError::Shape);
    }
    let mut internal = [F128::ZERO; STATE_SIZE];
    let mut pending = Vec::new();
    let mut shift_cursor = 0usize;
    for (reference, value) in references.iter().zip(values) {
        match reference {
            ColRef::Committed(column) => pending.push(MerkleColumnClaim {
                column: *column,
                point: point.to_vec(),
                value: *value,
            }),
            ColRef::Internal(lane) if *lane < STATE_SIZE => internal[*lane] = *value,
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let shift = proof_shifts
                    .get(shift_cursor)
                    .ok_or(MerkleUnionVerifyError::Shape)?;
                shift_cursor += 1;
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let shifted_point = if shift_log == 0 {
                    verify_shift_discharge(w_log, point, *value, shift, challenger)
                } else {
                    verify_shift_discharge_pow2(w_log, point, *value, 1, shift, challenger)
                }
                .map_err(MerkleUnionVerifyError::Shift)?;
                pending.push(MerkleColumnClaim {
                    column: *column,
                    point: shifted_point,
                    value: shift.final_value,
                });
            }
            _ => return Err(MerkleUnionVerifyError::Shape),
        }
    }
    if shift_cursor != proof_shifts.len() {
        return Err(MerkleUnionVerifyError::Shape);
    }
    Ok((internal, pending))
}

/// Prove Walk-B's zero and carry-selection prefix, stopping immediately
/// before the deep-chain walk.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_merkle_union_walk_prefix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    committed: &[&[F128]],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> MerkleUnionProverWalkPrefix {
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    assert!(s_out.iter().all(|column| column.len() == w));

    let lambda = challenger.sample_f128();
    let zero_terms = merkle_protocol_zero_terms(families, lambda);
    let zero_rho = challenger.sample_f128_vec(w_log);
    let (zero, zero_point, _) = prove_column_relation(
        F128::ZERO,
        &zero_rho,
        &zero_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        challenger,
    );
    let (_, mut pending, zero_shifts) = prove_merkle_claim_pass(
        committed,
        &claimed_refs(&zero_terms),
        &zero.final_values,
        &zero_point,
        challenger,
    );

    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(cb_c, beta);
    let selection_rho = challenger.sample_f128_vec(w_log);
    let internal_columns: Vec<&[F128]> = s_out.iter().map(Vec::as_slice).collect();
    let (selection, selection_point, _) = prove_column_relation(
        F128::ZERO,
        &selection_rho,
        &selection_terms,
        &RelationColumns {
            committed,
            internal: &internal_columns,
            fixed,
        },
        challenger,
    );
    let (output_values, selection_pending, selection_shifts) = prove_merkle_claim_pass(
        committed,
        &claimed_refs(&selection_terms),
        &selection.final_values,
        &selection_point,
        challenger,
    );
    assert!(selection_shifts.is_empty(), "Walk-B selection shifts");
    pending.extend(selection_pending);

    MerkleUnionProverWalkPrefix {
        zero,
        zero_shifts,
        selection,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    }
}

/// Finish Walk-B after a caller-owned walk and return a proof authority which
/// contains no embedded walk.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_merkle_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    families: &[MerkleProtocolFamily],
    committed: &[&[F128]],
    prefix: MerkleUnionProverWalkPrefix,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> (MerkleUnionWalkDeferredProof, Vec<MerkleColumnClaim>) {
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    let MerkleUnionProverWalkPrefix {
        zero,
        zero_shifts,
        selection,
        mut pending,
        walk_group: _,
    } = prefix;

    let alpha = challenger.sample_f128();
    let substitution_terms = merkle_protocol_substitution_terms(families, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let (substitution, substitution_point, _) = prove_column_relation(
        target,
        &terminal.point,
        &substitution_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        challenger,
    );
    let (_, substitution_pending, shifts) = prove_merkle_claim_pass(
        committed,
        &claimed_refs(&substitution_terms),
        &substitution.final_values,
        &substitution_point,
        challenger,
    );
    pending.extend(substitution_pending);

    (
        MerkleUnionWalkDeferredProof {
            zero,
            zero_shifts,
            selection,
            substitution,
            shifts,
        },
        pending,
    )
}

/// Verify Walk-B through carry selection and expose its caller-owned walk
/// group without accepting any walk proof in this phase.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_merkle_union_walk_prefix_with_challenger<'a, Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    proof: MerkleUnionWalkDeferredProofRef<'a>,
    challenger: &mut Ch,
) -> Result<MerkleUnionVerifierWalkPrefix<'a>, MerkleUnionVerifyError> {
    let lambda = challenger.sample_f128();
    let zero_terms = merkle_protocol_zero_terms(families, lambda);
    let zero_rho = challenger.sample_f128_vec(w_log);
    let zero_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &zero_rho,
        &zero_terms,
        fixed,
        proof.zero,
        challenger,
    )
    .map_err(MerkleUnionVerifyError::Zero)?;
    let (_, mut pending) = verify_merkle_claim_pass(
        w_log,
        &claimed_refs(&zero_terms),
        &proof.zero.final_values,
        &zero_point,
        proof.zero_shifts,
        challenger,
    )?;

    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(cb_c, beta);
    let selection_rho = challenger.sample_f128_vec(w_log);
    let selection_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &selection_rho,
        &selection_terms,
        fixed,
        proof.selection,
        challenger,
    )
    .map_err(MerkleUnionVerifyError::Selection)?;
    let (output_values, selection_pending) = verify_merkle_claim_pass(
        w_log,
        &claimed_refs(&selection_terms),
        &proof.selection.final_values,
        &selection_point,
        &[],
        challenger,
    )?;
    pending.extend(selection_pending);

    Ok(MerkleUnionVerifierWalkPrefix {
        proof,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    })
}

/// Verify the Walk-B substitution suffix against an externally verified walk
/// terminal and reconstruct the terminal PCS claims.
pub(crate) fn verify_merkle_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    families: &[MerkleProtocolFamily],
    prefix: MerkleUnionVerifierWalkPrefix<'_>,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> Result<Vec<MerkleColumnClaim>, MerkleUnionVerifyError> {
    let MerkleUnionVerifierWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = challenger.sample_f128();
    let substitution_terms = merkle_protocol_substitution_terms(families, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let substitution_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &substitution_terms,
        fixed,
        proof.substitution,
        challenger,
    )
    .map_err(MerkleUnionVerifyError::Substitution)?;
    let (_, substitution_pending) = verify_merkle_claim_pass(
        w_log,
        &claimed_refs(&substitution_terms),
        &proof.substitution.final_values,
        &substitution_point,
        proof.shifts,
        challenger,
    )?;
    pending.extend(substitution_pending);
    Ok(pending)
}

/// Prove the complete Walk-B union on a challenger already bound to the outer
/// witness commitment and statement.  This function intentionally has no
/// challenger-constructing shortcut.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_merkle_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> (MerkleUnionProof, Vec<MerkleColumnClaim>) {
    let w = 1usize << w_log;
    assert!(s0.iter().all(|column| column.len() == w));
    let prefix = prove_merkle_union_walk_prefix_with_challenger(
        w_log, fixed, cb_c, families, committed, s_out, challenger,
    );
    let groups = [prefix.walk_group().clone()];
    let (walk, terminal) = prove_deep_chain_walk(s0, &groups, challenger);
    let (deferred, pending) = prove_merkle_union_walk_suffix_with_challenger(
        w_log, fixed, families, committed, prefix, &terminal, challenger,
    );
    (
        MerkleUnionProof {
            zero: deferred.zero,
            zero_shifts: deferred.zero_shifts,
            selection: deferred.selection,
            walk,
            substitution: deferred.substitution,
            shifts: deferred.shifts,
        },
        pending,
    )
}

/// Verify [`prove_merkle_union_with_challenger`] and reconstruct all terminal
/// committed-column claims from the fixed family layout.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_merkle_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    proof: &MerkleUnionProof,
    challenger: &mut Ch,
) -> Result<Vec<MerkleColumnClaim>, MerkleUnionVerifyError> {
    let deferred = proof.walk_deferred();
    let prefix = verify_merkle_union_walk_prefix_with_challenger(
        w_log, fixed, cb_c, families, deferred, challenger,
    )?;
    let groups = [prefix.walk_group().clone()];
    let terminal = verify_deep_chain_walk(w_log, &groups, &proof.walk, challenger)
        .map_err(MerkleUnionVerifyError::Walk)?;
    verify_merkle_union_walk_suffix_with_challenger(
        w_log, fixed, families, prefix, &terminal, challenger,
    )
}

/// Place a prefix of paired-update columns into the shared nine-column meta-B
/// layout `C0..C3,E0,E1,SIB0,SIB1,D`.
fn place_paired_merkle_updates(
    cb: &mut [Vec<F128>],
    s0b: &mut [Vec<F128>; STATE_SIZE],
    soutb: &mut [Vec<F128>; STATE_SIZE],
    cols: &super::paired_merkle_update::PairedMerkleUpdateColumns,
    base: usize,
    n_slots: usize,
) {
    let range = base..base + n_slots;
    for lane in 0..STATE_SIZE {
        cb[lane][range.clone()].copy_from_slice(&cols.c[lane][..n_slots]);
        s0b[lane][range.clone()].copy_from_slice(&cols.s0[lane][..n_slots]);
        soutb[lane][range.clone()].copy_from_slice(&cols.s_out[lane][..n_slots]);
    }
    for lane in 0..2 {
        cb[4 + lane][range.clone()].copy_from_slice(&cols.e[lane][..n_slots]);
        cb[6 + lane][range.clone()].copy_from_slice(&cols.sib[lane][..n_slots]);
    }
    cb[8][range].copy_from_slice(&cols.d[..n_slots]);
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
    run_merkle_union_native_with_paired(
        committed,
        s0,
        s_out,
        fixed,
        cb_c,
        ff_specs,
        legs,
        &[],
        w_log,
        domain,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_merkle_union_native_with_paired(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    paired_specs: &[PairedMerkleSpec],
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
    let zero_terms = union_zero_terms(legs, ff_specs, paired_specs, lambda);
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
    let sub_terms = union_sub_terms_native(ff_specs, legs, paired_specs, alpha);
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
    ch: &mut impl FsChannelOps,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    w_log: usize,
    native: &MerkleUnionNative,
) -> (Vec<Claim>, Vec<(usize, usize, LinExpr)>) {
    discharge_merkle_union_with_paired(b, ch, fixed, cb_c, ff_specs, legs, &[], w_log, native)
}

#[allow(clippy::too_many_arguments)]
fn discharge_merkle_union_with_paired(
    b: &mut FieldR1csBuilder,
    mut ch: &mut impl FsChannelOps,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    paired_specs: &[PairedMerkleSpec],
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
    let zero_ref = union_zero_terms(legs, ff_specs, paired_specs, F128::ONE);
    let n_zero = claimed_refs(&zero_ref).len();
    let rho_b = ch.sample_f128_vec(b, w_log);
    let zero_e = ColumnRelationProofTrace::alloc(b, &native.zero_proof, w_log, n_zero);
    let zero_terms_e = union_zero_terms_trace(b, legs, ff_specs, paired_specs, &lambda);
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
    let (sub_terms, ap) = union_sub_terms_trace(b, ff_specs, legs, paired_specs, &alpha);
    let ref_terms = union_sub_terms_native(ff_specs, legs, paired_specs, F128::ONE);
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
    let seeds = channel.get_random_points(capsule_query_seed_count(nv + CAPSULE_LOG_RATE));
    let queries = capsule_queries_from_seeds(&seeds, nv + CAPSULE_LOG_RATE);
    debug_assert!(queries.iter().all(|&query| query <= mask as usize));
    queries
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

/// Serializable proof authority for one duplex-union sidecar.  Terminal PCS
/// descriptors are deliberately absent: their column, point and value are
/// reconstructed while replaying this proof against the verification key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DuplexUnionProof {
    pub(crate) selection: ColumnRelationProof,
    pub(crate) walk: DeepChainWalkProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
}

/// Serializable duplex authority with its deep-chain walk deferred to an
/// enclosing protocol.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DuplexUnionWalkDeferredProof {
    pub(crate) selection: ColumnRelationProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
}

#[derive(Clone, Copy)]
pub(crate) struct DuplexUnionWalkDeferredProofRef<'a> {
    pub(crate) selection: &'a ColumnRelationProof,
    pub(crate) substitution: &'a ColumnRelationProof,
    pub(crate) shifts: &'a [ShiftDischargeProof],
}

impl DuplexUnionProof {
    pub(crate) fn walk_deferred(&self) -> DuplexUnionWalkDeferredProofRef<'_> {
        DuplexUnionWalkDeferredProofRef {
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
        }
    }
}

impl DuplexUnionWalkDeferredProof {
    pub(crate) fn as_ref(&self) -> DuplexUnionWalkDeferredProofRef<'_> {
        DuplexUnionWalkDeferredProofRef {
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
        }
    }
}

pub(crate) struct DuplexUnionProverWalkPrefix {
    selection: ColumnRelationProof,
    pending: Vec<DuplexColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl DuplexUnionProverWalkPrefix {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

pub(crate) struct DuplexUnionVerifierWalkPrefix<'a> {
    proof: DuplexUnionWalkDeferredProofRef<'a>,
    pending: Vec<DuplexColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl DuplexUnionVerifierWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

/// A terminal opening on one of the six duplex committed columns.  This is a
/// transient replay result, never serialized into [`DuplexUnionProof`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DuplexColumnClaim {
    pub(crate) column: usize,
    pub(crate) point: Vec<F128>,
    pub(crate) value: F128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DuplexUnionVerifyError {
    Shape,
    Selection(RelationError),
    Walk(WalkError),
    Substitution(RelationError),
    Shift(RelationError),
}

fn duplex_terms_from_refs(
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    alpha: F128,
) -> Vec<RelationTerm> {
    if rec_refs.is_empty() {
        duplex_substitution_terms(refs, alpha)
    } else {
        let mut sets = vec![*refs];
        sets.extend_from_slice(rec_refs);
        duplex_substitution_terms_multi(&sets, alpha)
    }
}

/// Prove the duplex carry-selection prefix and stop before the deep-chain
/// walk.  The caller receives one exact walk group and cannot obtain a
/// deferred authority until it supplies the walk terminal to the suffix.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_duplex_union_walk_prefix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    committed: &[&[F128]],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> DuplexUnionProverWalkPrefix {
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    assert!(s_out.iter().all(|column| column.len() == w));

    let mut pending = Vec::new();
    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(&refs.c, beta);
    let rho = challenger.sample_f128_vec(w_log);
    let internal: Vec<&[F128]> = s_out.iter().map(Vec::as_slice).collect();
    let (selection, selection_point, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &selection_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        challenger,
    );
    let mut output_values = [F128::ZERO; STATE_SIZE];
    for (reference, value) in claimed_refs(&selection_terms)
        .iter()
        .zip(selection.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(DuplexColumnClaim {
                column: *column,
                point: selection_point.clone(),
                value: *value,
            }),
            ColRef::Internal(lane) => output_values[*lane] = *value,
            _ => unreachable!("duplex selection claim kind"),
        }
    }

    DuplexUnionProverWalkPrefix {
        selection,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    }
}

/// Finish the duplex substitution and shift discharges after a caller-owned
/// walk has produced `terminal`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_duplex_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    committed: &[&[F128]],
    prefix: DuplexUnionProverWalkPrefix,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> (DuplexUnionWalkDeferredProof, Vec<DuplexColumnClaim>) {
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    let DuplexUnionProverWalkPrefix {
        selection,
        mut pending,
        walk_group: _,
    } = prefix;

    let alpha = challenger.sample_f128();
    let substitution_terms = duplex_terms_from_refs(refs, rec_refs, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let (substitution, substitution_point, _) = prove_column_relation(
        target,
        &terminal.point,
        &substitution_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        challenger,
    );

    let mut shifts = Vec::new();
    for (reference, value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(substitution.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(DuplexColumnClaim {
                column: *column,
                point: substitution_point.clone(),
                value: *value,
            }),
            ColRef::CommittedShift(column) => {
                let (shift, point) = prove_shift_discharge(
                    committed[*column],
                    &substitution_point,
                    *value,
                    challenger,
                );
                pending.push(DuplexColumnClaim {
                    column: *column,
                    point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            _ => unreachable!("duplex substitution claim kind"),
        }
    }

    (
        DuplexUnionWalkDeferredProof {
            selection,
            substitution,
            shifts,
        },
        pending,
    )
}

/// Verify the duplex selection prefix and expose its exact caller-owned walk
/// group.
pub(crate) fn verify_duplex_union_walk_prefix_with_challenger<'a, Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    proof: DuplexUnionWalkDeferredProofRef<'a>,
    challenger: &mut Ch,
) -> Result<DuplexUnionVerifierWalkPrefix<'a>, DuplexUnionVerifyError> {
    let mut pending = Vec::new();
    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(&refs.c, beta);
    let rho = challenger.sample_f128_vec(w_log);
    let selection_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &selection_terms,
        fixed,
        proof.selection,
        challenger,
    )
    .map_err(DuplexUnionVerifyError::Selection)?;
    let mut output_values = [F128::ZERO; STATE_SIZE];
    for (reference, value) in claimed_refs(&selection_terms)
        .iter()
        .zip(proof.selection.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(DuplexColumnClaim {
                column: *column,
                point: selection_point.clone(),
                value: *value,
            }),
            ColRef::Internal(lane) if *lane < STATE_SIZE => output_values[*lane] = *value,
            _ => return Err(DuplexUnionVerifyError::Shape),
        }
    }

    Ok(DuplexUnionVerifierWalkPrefix {
        proof,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    })
}

/// Verify the duplex suffix against an externally verified walk terminal.
pub(crate) fn verify_duplex_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    prefix: DuplexUnionVerifierWalkPrefix<'_>,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> Result<Vec<DuplexColumnClaim>, DuplexUnionVerifyError> {
    let DuplexUnionVerifierWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = challenger.sample_f128();
    let substitution_terms = duplex_terms_from_refs(refs, rec_refs, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let substitution_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &substitution_terms,
        fixed,
        proof.substitution,
        challenger,
    )
    .map_err(DuplexUnionVerifyError::Substitution)?;

    let mut shift_cursor = 0usize;
    for (reference, value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(proof.substitution.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(DuplexColumnClaim {
                column: *column,
                point: substitution_point.clone(),
                value: *value,
            }),
            ColRef::CommittedShift(column) => {
                let shift = proof
                    .shifts
                    .get(shift_cursor)
                    .ok_or(DuplexUnionVerifyError::Shape)?;
                shift_cursor += 1;
                let point =
                    verify_shift_discharge(w_log, &substitution_point, *value, shift, challenger)
                        .map_err(DuplexUnionVerifyError::Shift)?;
                pending.push(DuplexColumnClaim {
                    column: *column,
                    point,
                    value: shift.final_value,
                });
            }
            _ => return Err(DuplexUnionVerifyError::Shape),
        }
    }
    if shift_cursor != proof.shifts.len() {
        return Err(DuplexUnionVerifyError::Shape);
    }
    Ok(pending)
}

/// Prover half of the duplex-union protocol over an already-bound transcript.
///
/// The caller owns transcript domain separation and, for a region sidecar,
/// MUST call this only after the outer witness commitment has been absorbed.
/// No challenger is constructed here: all challenges are drawn from the exact
/// challenger passed by the outer FieldR1cs prover.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_duplex_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> (DuplexUnionProof, Vec<DuplexColumnClaim>) {
    let w = 1usize << w_log;
    assert!(s0.iter().all(|column| column.len() == w));
    let prefix = prove_duplex_union_walk_prefix_with_challenger(
        w_log, fixed, refs, committed, s_out, challenger,
    );
    let groups = [prefix.walk_group().clone()];
    let (walk, terminal) = prove_deep_chain_walk(s0, &groups, challenger);
    let (deferred, pending) = prove_duplex_union_walk_suffix_with_challenger(
        w_log, fixed, refs, rec_refs, committed, prefix, &terminal, challenger,
    );
    (
        DuplexUnionProof {
            selection: deferred.selection,
            walk,
            substitution: deferred.substitution,
            shifts: deferred.shifts,
        },
        pending,
    )
}

/// Verifier half of [`prove_duplex_union_with_challenger`].  Every returned
/// terminal descriptor is derived from the proof replay and the caller's
/// fixed refs; no prover-supplied pending-claim list is consumed.
pub(crate) fn verify_duplex_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    proof: &DuplexUnionProof,
    challenger: &mut Ch,
) -> Result<Vec<DuplexColumnClaim>, DuplexUnionVerifyError> {
    let deferred = proof.walk_deferred();
    let prefix =
        verify_duplex_union_walk_prefix_with_challenger(w_log, fixed, refs, deferred, challenger)?;
    let groups = [prefix.walk_group().clone()];
    let terminal = verify_deep_chain_walk(w_log, &groups, &proof.walk, challenger)
        .map_err(DuplexUnionVerifyError::Walk)?;
    verify_duplex_union_walk_suffix_with_challenger(
        w_log, fixed, refs, rec_refs, prefix, &terminal, challenger,
    )
}

/// Native discharge of the whole channel union in ONE walk (mirror of
/// `run_leaf_union_native` with the duplex family's terms).
pub(crate) fn run_duplex_union_native(u: &DuplexUnion, domain: &[u8]) -> DuplexUnionNative {
    let committed: Vec<&[F128]> = u.committed.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let (proof, prover_claims) = prove_duplex_union_with_challenger(
        u.w_log,
        &u.fixed,
        &u.refs,
        &u.rec_refs,
        &committed,
        &u.s0,
        &u.s_out,
        &mut ch_p,
    );
    let verifier_claims = verify_duplex_union_with_challenger(
        u.w_log,
        &u.fixed,
        &u.refs,
        &u.rec_refs,
        &proof,
        &mut ch_v,
    )
    .expect("native duplex union");
    assert_eq!(prover_claims, verifier_claims, "duplex terminal claims");
    assert_eq!(
        ch_p.sample_f128(),
        ch_v.sample_f128(),
        "native duplex-union lockstep"
    );

    let shift_columns: Vec<usize> = claimed_refs(&duplex_union_sub_terms(u, F128::ONE))
        .iter()
        .filter_map(|reference| match reference {
            ColRef::CommittedShift(column) => Some(*column),
            _ => None,
        })
        .collect();
    assert_eq!(shift_columns.len(), proof.shifts.len());
    let shifts = shift_columns
        .into_iter()
        .zip(proof.shifts.iter().cloned())
        .map(|(column, shift)| (0usize, column, shift))
        .collect();
    let pending = prover_claims
        .into_iter()
        .map(|claim| (claim.column, claim.point, claim.value))
        .collect();
    DuplexUnionNative {
        sel_proof: proof.selection,
        walk_proof: proof.walk,
        sub_proof: proof.substitution,
        shifts,
        pending,
    }
}

/// Trace twin of `duplex_substitution_terms`: the α-batched walk-terminal wiring
/// `Σ_j m_j·[C_j(w−1) + START·C_j(w−1) + ABS_j·A_j + CONST_j]` (rate-lane absorbs
/// on j ∈ {0,1}), with `m_j = Σ_e α^{e+1}·flat(MDS[e][j])` built in-trace.
pub(crate) fn duplex_sub_terms_trace(
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

    /// Production C->D construction invariant without paying D's 2.1M-row
    /// inline twin in this unit: two independent recorder passes over the same
    /// C native proof are byte/value identical, and the recording becomes ONE
    /// ordinary D channel block (never the two-region builder's extra half).
    /// Every recorded data/challenge value occupies its exact D A/C cell.
    #[test]
    fn c_to_recording_only_d_scratch_is_exact_and_single_block() {
        let layout = compile_duplex(&channel_ops());
        let data: Vec<Vec<F128>> = (0..2)
            .map(|t| tx_data(&layout, 0xD1E7_0000 + t as u64))
            .collect();
        let u_c = build_duplex_union(&layout, iv_flat(), &data);
        let native_c = run_duplex_union_native(&u_c, DOMAIN_C);

        let record = || {
            let mut b = FieldR1csBuilder::new_witness_only();
            let mut ch = FsChannelUnionRecorder::new(DOMAIN_C);
            let claims = discharge_duplex_union(&mut b, &mut ch, &u_c, &native_c, 0);
            let rec = ch.finish();
            let challenges: Vec<F128> = rec
                .challenge_wires
                .iter()
                .map(|w| w.eval(b.values()))
                .collect();
            (rec, challenges, claims.len())
        };
        let (scratch, scratch_challenges, scratch_claims) = record();
        let (real, real_challenges, real_claims) = record();
        assert_eq!(real.ops, scratch.ops, "C recorder schedule parity");
        assert_eq!(real.data_flat, scratch.data_flat, "C recorder data parity");
        assert_eq!(
            real.post_state, scratch.post_state,
            "C recorder state parity"
        );
        assert_eq!(real.perms, scratch.perms, "C recorder permutation parity");
        assert_eq!(real_challenges, scratch_challenges, "C challenge parity");
        assert_eq!(real_claims, scratch_claims, "C claim-count parity");

        let d_layout = compile_duplex(&scratch.ops);
        let d_slots = d_layout.slots.len().max(1).next_power_of_two();
        let u_d = build_duplex_union(
            &d_layout,
            FsChannelUnionRecorder::capacity_iv_flat(),
            std::slice::from_ref(&scratch.data_flat),
        );
        assert_eq!(u_d.committed.len(), 6, "D committed column count");
        assert_eq!(u_d.committed[0].len(), d_slots, "one D schedule block");
        assert!(u_d.rec_blocks.is_empty(), "D must not grow a region-2 half");
        assert_eq!(u_d.challenges.len(), 1, "one hosted C transcript");
        assert_eq!(u_d.challenges[0], scratch_challenges, "D challenge cells");
        for (kk, &(slot, lane)) in duplex_data_positions(&d_layout).iter().enumerate() {
            assert_eq!(
                u_d.committed[u_d.refs.a[lane]][slot], scratch.data_flat[kk],
                "D data cell {kk}"
            );
        }
        for (kk, &(slot, lane)) in d_layout.challenges.iter().enumerate() {
            assert_eq!(
                u_d.committed[u_d.refs.c[lane]][slot], scratch_challenges[kk],
                "D challenge cell {kk}"
            );
        }
        let native_d = run_duplex_union_native(&u_d, DOMAIN_D);
        assert_eq!(native_d.pending.len(), scratch_claims, "D claim shape");
    }

    /// The production handoff uses exact cell equalities, not a known linear
    /// mix. Honest C recording wires satisfy them; mixing D columns built from
    /// another recording, or flipping either a hosted data/challenge cell,
    /// breaks the relation.
    #[test]
    fn c_to_d_exact_pins_reject_component_mix_and_cell_mutations() {
        fn record(b: &mut FieldR1csBuilder, seed: u64) -> RecordedChannel {
            let wires: Vec<LinExpr> = (0..12)
                .map(|i| {
                    LinExpr::from_wire(b.alloc_f128(F128 {
                        lo: seed.wrapping_add(i as u64),
                        hi: seed.rotate_left(23) ^ (17 * i as u64),
                    }))
                })
                .collect();
            let mut ch = FsChannelUnionRecorder::new(b"c-to-d-pin-source");
            ch.observe_label(b, b"hosted-C-proof");
            ch.observe_f128_slice(b, &wires);
            let _ = ch.sample_f128(b);
            ch.observe_f128(b, &wires[3]);
            let _ = ch.sample_f128_vec(b, 3);
            ch.finish()
        }

        let build = |host_seed: u64, wire_seed: u64| {
            let host = {
                let mut scratch = FieldR1csBuilder::new_witness_only();
                record(&mut scratch, host_seed)
            };
            let layout = compile_duplex(&host.ops);
            let u_d = build_duplex_union(
                &layout,
                FsChannelUnionRecorder::capacity_iv_flat(),
                std::slice::from_ref(&host.data_flat),
            );
            let mut b = FieldR1csBuilder::new();
            let real = record(&mut b, wire_seed);
            assert_eq!(real.ops, host.ops, "class-fixed recording schedule");
            let slices: Vec<WitnessSlice> = u_d
                .committed
                .iter()
                .map(|col| alloc_column_slice(&mut b, col, u_d.w_log).0)
                .collect();
            for (kk, &(slot, lane)) in layout.challenges.iter().enumerate() {
                pin_eq(
                    &mut b,
                    &real.challenge_wires[kk],
                    &slot_cell(&slices[u_d.refs.c[lane]], slot),
                );
            }
            let data_positions = duplex_data_positions(&layout);
            for (kk, &(slot, lane)) in data_positions.iter().enumerate() {
                pin_eq(
                    &mut b,
                    &real.data_wires[kk],
                    &slot_cell(&slices[u_d.refs.a[lane]], slot),
                );
            }
            let first_data = {
                let (slot, lane) = data_positions[0];
                slices[u_d.refs.a[lane]].start() + slot
            };
            let first_challenge = {
                let (slot, lane) = layout.challenges[0];
                slices[u_d.refs.c[lane]].start() + slot
            };
            let (r1cs, witness) = b.build();
            (r1cs, witness, first_data, first_challenge)
        };

        let (r1cs, honest, data_cell, challenge_cell) = build(0xC001, 0xC001);
        assert!(r1cs.satisfies(&honest), "honest C->D pins");
        for cell in [data_cell, challenge_cell] {
            let mut bad = honest.clone();
            bad[cell] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "mutated hosted D cell {cell}");
        }

        let (mixed_r1cs, mixed, _, _) = build(0xC001, 0xC002);
        assert!(
            !mixed_r1cs.satisfies(&mixed),
            "C proof wires mixed with another D recording"
        );
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
    use noid_ivc_core::verifier::{
        verify_field_with_public_io, verify_field_with_public_io_and_post_commit, VerifyError,
    };
    use noid_ivc_prover::field_prover::{
        prove_field_with_public_io, prove_field_with_public_io_and_post_commit,
    };

    use crate::acceptance::trace::owner_auth::build_owner_auth_slot;
    use crate::region_sidecar::{
        verify_duplex_region_sidecar, DuplexRegionProverPlan, DUPLEX_REGION_COMMITTED_COLUMNS,
    };

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

    /// Production preparation stops before every legacy discharge/recording,
    /// yet its exact six committed slices close through the post-commit
    /// sidecar and retain both transcript-data and squeezed-challenge pins.
    #[test]
    fn owner_auth_postcommit_preparation_is_canonical_and_proves() {
        const OUTER: &[u8] = b"owner-auth-c-prime-postcommit-preparation";
        let (proof, public) = fixture(0xC0FFEE);
        let mut b = FieldR1csBuilder::new();
        let proof_t = OwnerAuthProofTrace::alloc(&mut b, &proof, public.layout);
        let input_t = OwnerAuthPublicInputsTrace::alloc(&mut b, &public);
        let preparation = prepare_owner_auth_killshots_via_region(
            &mut b,
            std::slice::from_ref(&proof_t),
            std::slice::from_ref(&input_t),
            std::slice::from_ref(&proof),
            std::slice::from_ref(&public),
        );

        assert_eq!(preparation.obligations.len(), 1);
        assert_eq!(
            preparation.duplex_vk.purpose(),
            &owner_auth_duplex_sidecar_purpose()
        );
        assert_eq!(
            preparation.duplex_vk.refs(),
            duplex_family_refs(0, 0),
            "owner C-prime committed/fixed refs"
        );
        assert_eq!(preparation.duplex_vk.fixed().len(), 7);
        assert!(
            preparation
                .duplex_vk
                .fixed()
                .iter()
                .all(|pattern| pattern.hi_gate.is_none()),
            "owner C-prime V1 has no recording gates"
        );
        let slices = preparation.duplex_vk.slices();
        assert_eq!(slices.len(), DUPLEX_REGION_COMMITTED_COLUMNS);
        let base = slices[0].index;
        for (column, slice) in slices.iter().enumerate() {
            assert_eq!(slice.log2_len, preparation.duplex_vk.w_log());
            assert_eq!(slice.index, base + column, "exact contiguous column order");
        }
        let expected = 1usize << preparation.duplex_vk.w_log();
        assert!(preparation
            .s0()
            .iter()
            .all(|column| column.len() == expected));
        assert!(preparation
            .s_out()
            .iter()
            .all(|column| column.len() == expected));

        let mut short_s0 = (*preparation.s0()).clone();
        short_s0[0].pop();
        assert!(
            DuplexRegionProverPlan::new(&preparation.duplex_vk, &short_s0, preparation.s_out(),)
                .is_err(),
            "malformed owned walk endpoint shape accepted"
        );

        let (io_slice, _) = alloc_column_slice(&mut b, &[F128::ONE], 0);
        let spec = PublicIoSpec {
            io_slice,
            io_len: 1,
            claims: Vec::new(),
        };
        let io = [F128::ONE];
        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "prepared owner C-prime is unsatisfiable"
        );

        // The preparation retained both kinds of exact R1CS cell pins.
        let layout = compile_duplex(&owner_auth_channel_schedule(&proof, &public).ops);
        let (challenge_slot, challenge_lane) = layout.challenges[0];
        let challenge_cell =
            slices[preparation.duplex_vk.refs().c[challenge_lane]].start() + challenge_slot;
        let mut bad_challenge = z.clone();
        bad_challenge[challenge_cell] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad_challenge),
            "squeezed-challenge cell lost its algebra pin"
        );
        let (data_slot, data_lane) = duplex_data_positions(&layout)[0];
        let data_cell = slices[preparation.duplex_vk.refs().a[data_lane]].start() + data_slot;
        let mut bad_data = z.clone();
        bad_data[data_cell] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad_data),
            "absorbed-data cell lost its algebra pin"
        );

        let params = PcsParams {
            m: r1cs.m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let plan = preparation
            .prover_plan()
            .expect("canonical owner C-prime plan");
        let mut prover = FsLaneChallenger::new(OUTER);
        let (field_proof, sidecar, commitment, _) = prove_field_with_public_io_and_post_commit(
            &r1cs,
            &z,
            &params,
            &spec,
            &io,
            &mut prover,
            |z, _, challenger| plan.prove(z, challenger).expect("owner C-prime proof"),
        );
        let mut verifier = FsLaneChallenger::new(OUTER);
        verify_field_with_public_io_and_post_commit(
            &r1cs,
            &commitment,
            &field_proof,
            &spec,
            &io,
            &sidecar,
            &mut verifier,
            |proof, challenger| {
                verify_duplex_region_sidecar(&preparation.duplex_vk, r1cs.m, proof, challenger)
                    .map_err(|_| VerifyError::Auxiliary)
            },
        )
        .expect("prepared owner C-prime verifies postcommit");

        let mut wrong_shape = FsLaneChallenger::new(OUTER);
        assert!(
            verify_duplex_region_sidecar(
                &preparation.duplex_vk,
                preparation.duplex_vk.w_log() - 1,
                &sidecar,
                &mut wrong_shape,
            )
            .is_err(),
            "sidecar accepted below its committed-column arity"
        );
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
