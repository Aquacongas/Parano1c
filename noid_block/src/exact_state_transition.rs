// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact authenticated UTXO-state transition used by production `BlockProof`.
//!
//! The block header state root is the UTXO sparse-Merkle root. A proof carries
//! only the canonical multiproof siblings shared by the old and new touched
//! leaves. On a one-level frontier growth, old leaves are authenticated against
//! `EXSTNOD(parent_root, zero_root[parent_depth])`; otherwise they authenticate
//! directly against the parent header root.

use noid_chain::exact_state_hash::{slot_leaf_hash, state_node_hash, zero_slot_roots, StateHash};
use noid_chain::fri_state::SlotValue;
use noid_chain::sparse_merkle::{
    build_multiproof, derive_structural_frontier_plan, evaluate_structural_frontier,
    expand_multiproof_paths, maximum_sibling_count_with_segment_cap, ExpandedMerklePath,
    SparseMerkleCache, SparseMerkleError, StructuralFrontierEvaluation, StructuralFrontierPlan,
    StructuralNodeRef, STRUCTURAL_FRONTIER_PAD,
};
use noid_chain::state_delta::ExactActionSurface;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    FixedFieldHashInputs, FixedFieldHashParams, MerklePathInputs, SlotLeafInputs, MAX_MERKLE_DEPTH,
};
use noid_poseidon2b::native::domain::TAG_EXSTNOD;

/// Maximum user transactions under the consensus semantic block budget.
pub const MAX_EXACT_USER_TXS: usize = noid_chain::consensus::params::BLOCK_MAX_USER_TXS;
/// Maximum bitmap-live touched slots plus the required coinbase output.
pub const MAX_EXACT_TOUCHED_SLOTS: usize =
    noid_chain::consensus::params::BLOCK_MAX_USER_ACTIONS + 1;
/// Exact analytical frontier capacity at maximum depth under the consensus
/// touched-slot and distinct-segment limits.
pub const MAX_EXACT_SLOT_SIBLINGS: usize = maximum_sibling_count_with_segment_cap(
    MAX_EXACT_TOUCHED_SLOTS,
    MAX_MERKLE_DEPTH as u32,
    noid_chain::consensus::params::LOG_SEGMENT_SIZE,
    noid_chain::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS,
);
/// Maximum binary combines needed to reconstruct one exact-state root.
pub const MAX_EXACT_FRONTIER_COMBINES: usize =
    MAX_EXACT_TOUCHED_SLOTS + MAX_EXACT_SLOT_SIBLINGS - 1;
/// Maximum raw sibling bytes under the analytical bound.
pub const MAX_EXACT_SLOT_SIBLING_BYTES: usize = MAX_EXACT_SLOT_SIBLINGS * 32;
/// Bincode's vector length prefix plus the complete sibling frontier.
pub const MAX_EXACT_STATE_PROOF_BYTES: usize = 8 + MAX_EXACT_SLOT_SIBLING_BYTES;
/// Maximum EXSTNOD compression claims placed in one fixed-field GKR proof.
///
/// Every claim consumes two Poseidon permutation slots, so this cap keeps a
/// chunk at `num_vars = 23` in the current dynamic block-spine layout.
pub const MAX_EXACT_STRUCTURAL_HASH_CLAIMS_PER_PROOF: usize = 8_192;

/// Exact authenticated state transition proof payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExactStateTransitionProof {
    /// Missing slot-frontier hashes in canonical implicit order.
    pub slot_siblings: Vec<StateHash>,
}

impl ExactStateTransitionProof {
    pub fn byte_len(&self) -> usize {
        self.slot_siblings.len() * 32
    }
}

/// Header roots/depths and parent counters known before proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateTransitionInputs {
    pub parent_state_root: StateHash,
    pub parent_log_slots: u32,
    pub child_state_root: StateHash,
    pub child_log_slots: u32,
    pub parent_active_slot_count: u64,
    pub parent_alloc_counter: u64,
}

/// Sealed transition object returned only after exact verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStateTransition {
    parent_state_root: StateHash,
    child_state_root: StateHash,
    log_slots: u32,
    slot_updates: Vec<(u32, SlotValue)>,
    active_slot_count: u64,
    alloc_counter: u64,
}

/// Public Merkle-path inputs consumed by the EXSTNOD batch relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateMerkleBatchInputs {
    pub old_root: StateHash,
    pub new_root: StateHash,
    pub old_paths: Vec<MerklePathInputs>,
    pub new_paths: Vec<MerklePathInputs>,
}

/// Public EXSTSLT slot-leaf inputs for old and new exact leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSlotLeafBatchInputs {
    pub old_leaves: Vec<SlotLeafInputs>,
    pub new_leaves: Vec<SlotLeafInputs>,
}

/// Deterministic proof-chunk geometry for the structural EXSTNOD carrier.
///
/// The logical statement always contains one class-capacity old-root half
/// followed by one class-capacity new-root half.  Each half is live-combine
/// prefix followed by canonical ghost combines.  Chunk boundaries are then
/// cut across that fixed logical statement without reordering it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateStructuralHashChunkPlan {
    pub combine_capacity_per_root: usize,
    pub total_claims: usize,
    pub chunk_lengths: Vec<usize>,
}

/// Fixed-field EXSTNOD statements derived from one structural frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateStructuralHashBatchInputs {
    pub old_root: StateHash,
    pub new_root: StateHash,
    pub live_combines_per_root: usize,
    pub chunk_plan: ExactStateStructuralHashChunkPlan,
    pub chunks: Vec<Vec<FixedFieldHashInputs>>,
}

impl ExactStateStructuralHashBatchInputs {
    /// Iterate in transcript order: padded old half, then padded new half.
    pub fn claims(&self) -> impl Iterator<Item = &FixedFieldHashInputs> {
        self.chunks.iter().flat_map(|chunk| chunk.iter())
    }
}

/// Sealed root-only result shared by native acceptance and proof projection.
///
/// Fields stay crate-private and there is no public constructor: retained
/// proof-input projection may reuse this object, but a verifier never accepts
/// witness-supplied roots or combine digests as an authority. Keeping path
/// expansion out of this step is what lets large statements stay path-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedExactStateRoots {
    pub(crate) old_root: StateHash,
    pub(crate) new_root: StateHash,
    pub(crate) old_leaf_hashes: Vec<StateHash>,
    pub(crate) new_leaf_hashes: Vec<StateHash>,
    pub(crate) old_combine_digests: Vec<StateHash>,
    pub(crate) new_combine_digests: Vec<StateHash>,
}

impl VerifiedStateTransition {
    /// Seal a natively recomputed no-user transition. The caller supplies the
    /// exact post-state root calculated from the same canonical slot updates.
    pub(crate) fn from_verified_no_spend_native(
        inputs: &ExactStateTransitionInputs,
        surface: &ExactActionSurface,
        child_state_root: StateHash,
    ) -> Result<Self, ExactStateTransitionError> {
        validate_depth_transition(inputs)?;
        if surface.touched_indices.len() != surface.old_slots.len()
            || surface.touched_indices.len() != surface.new_slots.len()
        {
            return Err(ExactStateTransitionError::SurfaceLengthMismatch);
        }
        if surface.touched_indices.is_empty() {
            if !surface.actions.is_empty() || surface.spends != 0 || surface.mints != 0 {
                return Err(ExactStateTransitionError::SurfaceLengthMismatch);
            }
            let expected_child = old_frontier_root(inputs)?;
            if child_state_root != expected_child || inputs.child_state_root != expected_child {
                return Err(ExactStateTransitionError::ChildRootMismatch);
            }
            return seal_exact_state_transition(inputs, surface);
        }
        if child_state_root != inputs.child_state_root {
            return Err(ExactStateTransitionError::ChildRootMismatch);
        }
        seal_exact_state_transition(inputs, surface)
    }

    pub fn parent_state_root(&self) -> StateHash {
        self.parent_state_root
    }

    pub fn child_state_root(&self) -> StateHash {
        self.child_state_root
    }

    pub fn log_slots(&self) -> u32 {
        self.log_slots
    }

    pub fn slot_updates(&self) -> &[(u32, SlotValue)] {
        &self.slot_updates
    }

    pub fn active_slot_count(&self) -> u64 {
        self.active_slot_count
    }

    pub fn alloc_counter(&self) -> u64 {
        self.alloc_counter
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateTransitionError {
    EmptyTouchedSet,
    TooManyTouchedSlots { actual: usize, maximum: usize },
    TooManyTouchedSegments { actual: usize, maximum: usize },
    TooManySpends { actual: u32, maximum: usize },
    TooManyMints { actual: u32, maximum: usize },
    SurfaceLengthMismatch,
    InvalidLogSlots,
    ParentRootMismatch,
    ChildRootMismatch,
    ProofTooLarge { siblings: usize },
    StructuralCombineCapacityExceeded { required: usize, capacity: usize },
    StructuralCombineCapacityTooLarge { capacity: usize, maximum: usize },
    CounterUnderflow,
    CounterOverflow,
    SparseMerkle(SparseMerkleError),
    ProofDepthUnsupported { depth: u32, max_depth: usize },
}

impl From<SparseMerkleError> for ExactStateTransitionError {
    fn from(err: SparseMerkleError) -> Self {
        Self::SparseMerkle(err)
    }
}

/// Build the canonical sibling-only proof from the cache at the child depth.
/// For a grow transition the caller passes the parent leaves embedded in the
/// one-level-grown cache, making the top right sibling the canonical zero root.
pub fn build_exact_state_transition_proof(
    cache: &SparseMerkleCache,
    surface: &ExactActionSurface,
) -> Result<ExactStateTransitionProof, ExactStateTransitionError> {
    validate_surface(surface)?;
    let proof = build_multiproof(cache, &surface.touched_indices, cache.depth())?;
    if proof.siblings.len() > MAX_EXACT_SLOT_SIBLINGS {
        return Err(ExactStateTransitionError::ProofTooLarge {
            siblings: proof.siblings.len(),
        });
    }
    Ok(ExactStateTransitionProof {
        slot_siblings: proof.siblings,
    })
}

/// Derive and fully bind the old/new EXSTNOD path statements.
pub fn derive_exact_state_merkle_batch_inputs(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
) -> Result<ExactStateMerkleBatchInputs, ExactStateTransitionError> {
    let roots = verify_exact_state_roots(inputs, surface, proof)?;

    derive_exact_state_merkle_batch_inputs_from_verified_roots(inputs, surface, proof, &roots)
}

/// Project transitional directed-path inputs from roots already authenticated
/// by [`verify_exact_state_roots`]. This is crate-private so untrusted callers
/// cannot bypass the root audit.
pub(crate) fn derive_exact_state_merkle_batch_inputs_from_verified_roots(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
    roots: &VerifiedExactStateRoots,
) -> Result<ExactStateMerkleBatchInputs, ExactStateTransitionError> {
    let old_expanded = expand_multiproof_paths(
        &surface.touched_indices,
        &roots.old_leaf_hashes,
        &proof.slot_siblings,
        inputs.child_log_slots,
    )?;
    let new_expanded = expand_multiproof_paths(
        &surface.touched_indices,
        &roots.new_leaf_hashes,
        &proof.slot_siblings,
        inputs.child_log_slots,
    )?;
    let old_paths = old_expanded
        .iter()
        .map(|path| expanded_to_gkr_path(path, roots.old_root, inputs.child_log_slots))
        .collect::<Result<Vec<_>, _>>()?;
    let new_paths = new_expanded
        .iter()
        .map(|path| expanded_to_gkr_path(path, roots.new_root, inputs.child_log_slots))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ExactStateMerkleBatchInputs {
        old_root: roots.old_root,
        new_root: roots.new_root,
        old_paths,
        new_paths,
    })
}

/// Parameters for the structural binary-node hash relation.
///
/// Four fields are exactly the two 32-byte children in little-endian lane
/// order.  The fixed no-padding schedule is byte-identical to
/// `state_node_hash(left, right)` under `TAG_EXSTNOD`.
pub fn exact_state_structural_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(TAG_EXSTNOD, 4)
        .expect("four fields are a valid fixed EXSTNOD schedule")
}

/// Canonical class-level chunk plan for old and new structural combines.
pub fn exact_state_structural_hash_chunk_plan(
    combine_capacity_per_root: usize,
) -> Result<ExactStateStructuralHashChunkPlan, ExactStateTransitionError> {
    if combine_capacity_per_root == 0 {
        return Err(
            ExactStateTransitionError::StructuralCombineCapacityExceeded {
                required: 1,
                capacity: 0,
            },
        );
    }
    if combine_capacity_per_root > MAX_EXACT_FRONTIER_COMBINES {
        return Err(
            ExactStateTransitionError::StructuralCombineCapacityTooLarge {
                capacity: combine_capacity_per_root,
                maximum: MAX_EXACT_FRONTIER_COMBINES,
            },
        );
    }

    let total_claims = 2 * combine_capacity_per_root;
    let mut remaining = total_claims;
    let mut chunk_lengths =
        Vec::with_capacity(total_claims.div_ceil(MAX_EXACT_STRUCTURAL_HASH_CLAIMS_PER_PROOF));
    while remaining != 0 {
        let chunk = remaining.min(MAX_EXACT_STRUCTURAL_HASH_CLAIMS_PER_PROOF);
        chunk_lengths.push(chunk);
        remaining -= chunk;
    }
    Ok(ExactStateStructuralHashChunkPlan {
        combine_capacity_per_root,
        total_claims,
        chunk_lengths,
    })
}

/// Canonical non-live EXSTNOD statement used after each root's live combines.
///
/// The all-zero digest is merely the structural PAD child value; its parent is
/// still the real domain-separated hash of two PAD children.  Keeping this a
/// valid hash statement lets every class retain fixed proof geometry without
/// treating a zero digest as an end-of-frontier sentinel.
pub fn exact_state_structural_hash_ghost_input() -> FixedFieldHashInputs {
    structural_hash_input(
        STRUCTURAL_FRONTIER_PAD,
        STRUCTURAL_FRONTIER_PAD,
        state_node_hash(STRUCTURAL_FRONTIER_PAD, STRUCTURAL_FRONTIER_PAD),
    )
}

/// Derive fixed-field EXSTNOD statements from the canonical structural plan.
///
/// Live claims preserve `StructuralFrontierPlan::combines()` order.  The flat
/// statement is:
///
/// ```text
/// old_live || old_ghosts_to_class_cap ||
/// new_live || new_ghosts_to_class_cap
/// ```
///
/// It is then split deterministically into chunks of at most 8,192 claims.
/// This is a prototype input carrier only; the production recursive backend
/// still consumes expanded paths until its topology/source binding is moved to
/// this structural statement.
pub fn derive_exact_state_structural_hash_batch_inputs(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
    combine_capacity_per_root: usize,
) -> Result<ExactStateStructuralHashBatchInputs, ExactStateTransitionError> {
    let roots = verify_exact_state_roots(inputs, surface, proof)?;
    let plan = derive_structural_frontier_plan(&surface.touched_indices, inputs.child_log_slots)?;
    let live_combines_per_root = plan.combines().len();
    if live_combines_per_root > combine_capacity_per_root {
        return Err(
            ExactStateTransitionError::StructuralCombineCapacityExceeded {
                required: live_combines_per_root,
                capacity: combine_capacity_per_root,
            },
        );
    }
    let chunk_plan = exact_state_structural_hash_chunk_plan(combine_capacity_per_root)?;

    let old_evaluation =
        evaluate_structural_frontier(&plan, &roots.old_leaf_hashes, &proof.slot_siblings)?;
    if old_evaluation.root != roots.old_root {
        return Err(ExactStateTransitionError::ParentRootMismatch);
    }
    let new_evaluation =
        evaluate_structural_frontier(&plan, &roots.new_leaf_hashes, &proof.slot_siblings)?;
    if new_evaluation.root != roots.new_root {
        return Err(ExactStateTransitionError::ChildRootMismatch);
    }

    let ghost = exact_state_structural_hash_ghost_input();
    let mut claims = Vec::with_capacity(chunk_plan.total_claims);
    claims.extend(structural_hash_inputs_for_root(
        &plan,
        &roots.old_leaf_hashes,
        &proof.slot_siblings,
        &old_evaluation,
    ));
    claims.resize(combine_capacity_per_root, ghost.clone());
    claims.extend(structural_hash_inputs_for_root(
        &plan,
        &roots.new_leaf_hashes,
        &proof.slot_siblings,
        &new_evaluation,
    ));
    claims.resize(chunk_plan.total_claims, ghost);

    let mut claims = claims.into_iter();
    let chunks = chunk_plan
        .chunk_lengths
        .iter()
        .map(|&len| claims.by_ref().take(len).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    debug_assert!(claims.next().is_none());

    Ok(ExactStateStructuralHashBatchInputs {
        old_root: roots.old_root,
        new_root: roots.new_root,
        live_combines_per_root,
        chunk_plan,
        chunks,
    })
}

fn structural_hash_inputs_for_root(
    plan: &StructuralFrontierPlan,
    leaves: &[StateHash],
    siblings: &[StateHash],
    evaluation: &StructuralFrontierEvaluation,
) -> Vec<FixedFieldHashInputs> {
    plan.combines()
        .iter()
        .enumerate()
        .map(|(ordinal, combine)| {
            let left = structural_node_value(combine.left, leaves, siblings, &evaluation.combines);
            let right =
                structural_node_value(combine.right, leaves, siblings, &evaluation.combines);
            structural_hash_input(left, right, evaluation.combines[ordinal])
        })
        .collect()
}

fn structural_node_value(
    node: StructuralNodeRef,
    leaves: &[StateHash],
    siblings: &[StateHash],
    combines: &[StateHash],
) -> StateHash {
    match node {
        StructuralNodeRef::TouchedLeaf(ordinal) => leaves[ordinal],
        StructuralNodeRef::FrontierSibling(ordinal) => siblings[ordinal],
        StructuralNodeRef::Combine(ordinal) => combines[ordinal],
    }
}

fn structural_hash_input(
    left: StateHash,
    right: StateHash,
    expected_parent: StateHash,
) -> FixedFieldHashInputs {
    let left = digest_to_fields(left);
    let right = digest_to_fields(right);
    FixedFieldHashInputs {
        fields: vec![left[0], left[1], right[0], right[1]],
        expected_digest: digest_to_fields(expected_parent),
    }
}

pub fn derive_exact_slot_leaf_batch_inputs(
    surface: &ExactActionSurface,
) -> Result<ExactSlotLeafBatchInputs, ExactStateTransitionError> {
    validate_surface(surface)?;
    let old_leaves = surface
        .old_slots
        .iter()
        .copied()
        .map(slot_to_leaf_input)
        .collect();
    let new_leaves = surface
        .new_slots
        .iter()
        .copied()
        .map(slot_to_leaf_input)
        .collect();
    Ok(ExactSlotLeafBatchInputs {
        old_leaves,
        new_leaves,
    })
}

pub fn verify_exact_state_transition(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
) -> Result<VerifiedStateTransition, ExactStateTransitionError> {
    verify_exact_state_transition_with_roots(inputs, surface, proof)
        .map(|(verified, _roots)| verified)
}

/// Verify both exact-state roots once and return the sealed transition together
/// with its reusable, non-serializable root audit artifact.
pub(crate) fn verify_exact_state_transition_with_roots(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
) -> Result<(VerifiedStateTransition, VerifiedExactStateRoots), ExactStateTransitionError> {
    let roots = verify_exact_state_roots(inputs, surface, proof)?;
    let verified = seal_exact_state_transition(inputs, surface)?;
    Ok((verified, roots))
}

pub(crate) fn seal_exact_state_transition(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
) -> Result<VerifiedStateTransition, ExactStateTransitionError> {
    // Keep sealing fail-closed even if a future crate-local caller bypasses
    // root verification. Empty is valid for the native no-op path; unequal
    // vectors are never valid and `zip` must not silently truncate them.
    if surface.touched_indices.len() != surface.old_slots.len()
        || surface.touched_indices.len() != surface.new_slots.len()
    {
        return Err(ExactStateTransitionError::SurfaceLengthMismatch);
    }
    let active_slot_count = inputs
        .parent_active_slot_count
        .checked_sub(surface.spends as u64)
        .ok_or(ExactStateTransitionError::CounterUnderflow)?
        .checked_add(surface.mints as u64)
        .ok_or(ExactStateTransitionError::CounterOverflow)?;
    let alloc_counter = inputs
        .parent_alloc_counter
        .checked_add(surface.mints as u64)
        .ok_or(ExactStateTransitionError::CounterOverflow)?;
    let slot_updates = surface
        .touched_indices
        .iter()
        .copied()
        .zip(surface.new_slots.iter().copied())
        .collect();

    Ok(VerifiedStateTransition {
        parent_state_root: inputs.parent_state_root,
        child_state_root: inputs.child_state_root,
        log_slots: inputs.child_log_slots,
        slot_updates,
        active_slot_count,
        alloc_counter,
    })
}

/// Authenticate the old and new touched leaves against the header boundary
/// without materialising per-leaf paths.  `reconstruct_root` consumes the
/// canonical multiproof frontier directly, so the ordinary accept path stays
/// O(frontier) in memory instead of O(touched_slots * depth).
pub(crate) fn verify_exact_state_roots(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
) -> Result<VerifiedExactStateRoots, ExactStateTransitionError> {
    validate_surface(surface)?;
    validate_depth_transition(inputs)?;
    validate_proof_shape(inputs, proof)?;

    let old_root = old_frontier_root(inputs)?;
    let old_leaf_hashes = hash_slots(&surface.old_slots);
    let new_leaf_hashes = hash_slots(&surface.new_slots);
    let plan = derive_structural_frontier_plan(&surface.touched_indices, inputs.child_log_slots)?;
    let old_evaluation =
        evaluate_structural_frontier(&plan, &old_leaf_hashes, &proof.slot_siblings)?;
    if old_evaluation.root != old_root {
        return Err(ExactStateTransitionError::ParentRootMismatch);
    }
    let new_evaluation =
        evaluate_structural_frontier(&plan, &new_leaf_hashes, &proof.slot_siblings)?;
    if new_evaluation.root != inputs.child_state_root {
        return Err(ExactStateTransitionError::ChildRootMismatch);
    }

    Ok(VerifiedExactStateRoots {
        old_root,
        new_root: inputs.child_state_root,
        old_leaf_hashes,
        new_leaf_hashes,
        old_combine_digests: old_evaluation.combines,
        new_combine_digests: new_evaluation.combines,
    })
}

fn validate_surface(surface: &ExactActionSurface) -> Result<(), ExactStateTransitionError> {
    if surface.touched_indices.is_empty() {
        return Err(ExactStateTransitionError::EmptyTouchedSet);
    }
    if surface.touched_indices.len() > MAX_EXACT_TOUCHED_SLOTS {
        return Err(ExactStateTransitionError::TooManyTouchedSlots {
            actual: surface.touched_indices.len(),
            maximum: MAX_EXACT_TOUCHED_SLOTS,
        });
    }
    let maximum_spends = noid_chain::consensus::params::BLOCK_MAX_LIVE_INPUTS;
    if surface.spends as usize > maximum_spends {
        return Err(ExactStateTransitionError::TooManySpends {
            actual: surface.spends,
            maximum: maximum_spends,
        });
    }
    let maximum_mints = noid_chain::consensus::params::BLOCK_MAX_USER_OUTPUTS + 1;
    if surface.mints as usize > maximum_mints {
        return Err(ExactStateTransitionError::TooManyMints {
            actual: surface.mints,
            maximum: maximum_mints,
        });
    }
    if surface.touched_indices.len() != surface.old_slots.len()
        || surface.touched_indices.len() != surface.new_slots.len()
    {
        return Err(ExactStateTransitionError::SurfaceLengthMismatch);
    }
    let segment_count = surface
        .touched_indices
        .iter()
        .map(|index| index >> noid_chain::consensus::params::LOG_SEGMENT_SIZE)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let maximum_segments = noid_chain::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS;
    if segment_count > maximum_segments {
        return Err(ExactStateTransitionError::TooManyTouchedSegments {
            actual: segment_count,
            maximum: maximum_segments,
        });
    }
    Ok(())
}

fn validate_depth_transition(
    inputs: &ExactStateTransitionInputs,
) -> Result<(), ExactStateTransitionError> {
    if inputs.child_log_slots as usize > MAX_MERKLE_DEPTH {
        return Err(ExactStateTransitionError::ProofDepthUnsupported {
            depth: inputs.child_log_slots,
            max_depth: MAX_MERKLE_DEPTH,
        });
    }
    match inputs.child_log_slots.cmp(&inputs.parent_log_slots) {
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Greater if inputs.child_log_slots == inputs.parent_log_slots + 1 => {
            Ok(())
        }
        _ => Err(ExactStateTransitionError::InvalidLogSlots),
    }
}

fn validate_proof_shape(
    inputs: &ExactStateTransitionInputs,
    proof: &ExactStateTransitionProof,
) -> Result<(), ExactStateTransitionError> {
    if proof.slot_siblings.len() > MAX_EXACT_SLOT_SIBLINGS {
        return Err(ExactStateTransitionError::ProofTooLarge {
            siblings: proof.slot_siblings.len(),
        });
    }
    if inputs.child_log_slots as usize > MAX_MERKLE_DEPTH {
        return Err(ExactStateTransitionError::ProofDepthUnsupported {
            depth: inputs.child_log_slots,
            max_depth: MAX_MERKLE_DEPTH,
        });
    }
    Ok(())
}

fn old_frontier_root(
    inputs: &ExactStateTransitionInputs,
) -> Result<StateHash, ExactStateTransitionError> {
    match inputs.child_log_slots.cmp(&inputs.parent_log_slots) {
        std::cmp::Ordering::Equal => Ok(inputs.parent_state_root),
        std::cmp::Ordering::Greater if inputs.child_log_slots == inputs.parent_log_slots + 1 => {
            let zeros = zero_slot_roots(inputs.parent_log_slots as usize);
            Ok(state_node_hash(
                inputs.parent_state_root,
                zeros[inputs.parent_log_slots as usize],
            ))
        }
        _ => Err(ExactStateTransitionError::InvalidLogSlots),
    }
}

fn slot_to_leaf_input(slot: SlotValue) -> SlotLeafInputs {
    SlotLeafInputs {
        packed_value: slot.value,
        owner_hi: slot.owner_hi,
        owner_lo: slot.owner_lo,
        expected_leaf: digest_to_fields(slot_leaf_hash(slot)),
    }
}

fn digest_to_fields(hash: StateHash) -> [Block128; 2] {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&hash[..16]);
    hi.copy_from_slice(&hash[16..]);
    [
        Block128::from(u128::from_le_bytes(lo)),
        Block128::from(u128::from_le_bytes(hi)),
    ]
}

fn expanded_to_gkr_path(
    path: &ExpandedMerklePath,
    expected_root: StateHash,
    depth: u32,
) -> Result<MerklePathInputs, ExactStateTransitionError> {
    let depth = depth as usize;
    if depth > MAX_MERKLE_DEPTH {
        return Err(ExactStateTransitionError::ProofDepthUnsupported {
            depth: depth as u32,
            max_depth: MAX_MERKLE_DEPTH,
        });
    }
    let mut siblings = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
    let mut directions = [false; MAX_MERKLE_DEPTH];
    for level in 0..depth {
        siblings[level] = digest_to_fields(path.siblings[level]);
        directions[level] = path.directions[level];
    }
    Ok(MerklePathInputs {
        leaf: digest_to_fields(path.leaf),
        siblings,
        directions,
        expected_root: digest_to_fields(expected_root),
        active_depth: depth,
    })
}

fn hash_slots(slots: &[SlotValue]) -> Vec<StateHash> {
    slots.iter().copied().map(slot_leaf_hash).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::exact_state_hash::slot_leaf_hash;
    use noid_chain::state_delta::{
        exact_action_surface_from_surface, StateDeltaAction, StateDeltaActionKind,
        StateDeltaActionSurface,
    };
    use noid_gkr::{
        discharge_fixed_field_hash_reductions_native, prove_fixed_field_hash_killshot,
        verify_fixed_field_hash_killshot,
    };
    use noid_poseidon2b::channel::Poseidon2bChannel;

    fn sv(value: u64, seed: u128) -> SlotValue {
        SlotValue {
            value: Block128::from(value),
            owner_hi: Block128::from(seed),
            owner_lo: Block128::from(seed + 1),
        }
    }

    fn surface(old: SlotValue, new: SlotValue) -> ExactActionSurface {
        exact_action_surface_from_surface(StateDeltaActionSurface {
            actions: vec![
                StateDeltaAction {
                    tx_index: 0,
                    op_index: 0,
                    slot_index: 2,
                    pre: old,
                    post: SlotValue::EMPTY,
                    kind: StateDeltaActionKind::Spend,
                },
                StateDeltaAction {
                    tx_index: 0,
                    op_index: 0,
                    slot_index: 5,
                    pre: SlotValue::EMPTY,
                    post: new,
                    kind: StateDeltaActionKind::Mint,
                },
            ],
            spends: 1,
            mints: 1,
        })
    }

    fn fixture(
        grow: bool,
    ) -> (
        ExactActionSurface,
        ExactStateTransitionInputs,
        ExactStateTransitionProof,
    ) {
        let old = sv(10, 100);
        let new = sv(7, 200);
        let surface = surface(old, new);
        let parent_depth = 4usize;
        let child_depth = parent_depth + usize::from(grow);
        let parent =
            SparseMerkleCache::from_leaves(parent_depth as u32, &[(2, slot_leaf_hash(old))])
                .unwrap();
        let proof_cache =
            SparseMerkleCache::from_leaves(child_depth as u32, &[(2, slot_leaf_hash(old))])
                .unwrap();
        let child = SparseMerkleCache::from_leaves(child_depth as u32, &[(5, slot_leaf_hash(new))])
            .unwrap();
        let inputs = ExactStateTransitionInputs {
            parent_state_root: parent.root(),
            parent_log_slots: parent_depth as u32,
            child_state_root: child.root(),
            child_log_slots: child_depth as u32,
            parent_active_slot_count: 1,
            parent_alloc_counter: 1,
        };
        let proof = build_exact_state_transition_proof(&proof_cache, &surface).unwrap();
        (surface, inputs, proof)
    }

    #[test]
    fn equal_depth_transition_binds_both_header_roots() {
        let (surface, inputs, proof) = fixture(false);
        let verified = verify_exact_state_transition(&inputs, &surface, &proof).unwrap();
        assert_eq!(verified.parent_state_root(), inputs.parent_state_root);
        assert_eq!(verified.child_state_root(), inputs.child_state_root);
        assert_eq!(verified.log_slots(), inputs.child_log_slots);
        assert_eq!(verified.active_slot_count(), 1);
        assert_eq!(verified.alloc_counter(), 2);

        let derived = derive_exact_state_merkle_batch_inputs(&inputs, &surface, &proof).unwrap();
        assert_eq!(derived.old_root, inputs.parent_state_root);
        assert_eq!(derived.new_root, inputs.child_state_root);
        assert!(derived
            .old_paths
            .iter()
            .chain(derived.new_paths.iter())
            .all(|path| path.active_depth == inputs.child_log_slots as usize));
    }

    #[test]
    fn grow_transition_uses_parent_plus_zero_frontier() {
        let (surface, inputs, proof) = fixture(true);
        let derived = derive_exact_state_merkle_batch_inputs(&inputs, &surface, &proof).unwrap();
        let zeros = zero_slot_roots(inputs.parent_log_slots as usize);
        let expected_old = state_node_hash(
            inputs.parent_state_root,
            zeros[inputs.parent_log_slots as usize],
        );
        assert_eq!(derived.old_root, expected_old);
        assert_eq!(derived.new_root, inputs.child_state_root);
        assert!(derived
            .old_paths
            .iter()
            .all(|path| path.expected_root == digest_to_fields(expected_old)));
        assert!(derived
            .new_paths
            .iter()
            .all(|path| path.expected_root == digest_to_fields(inputs.child_state_root)));
        verify_exact_state_transition(&inputs, &surface, &proof).unwrap();
    }

    #[test]
    fn structural_hash_inputs_follow_old_then_new_plan_order() {
        let (surface, inputs, proof) = fixture(false);
        let plan =
            derive_structural_frontier_plan(&surface.touched_indices, inputs.child_log_slots)
                .unwrap();
        let live = plan.combines().len();
        let capacity = live + 3;
        let batch =
            derive_exact_state_structural_hash_batch_inputs(&inputs, &surface, &proof, capacity)
                .unwrap();
        let claims = batch.claims().collect::<Vec<_>>();
        let ghost = exact_state_structural_hash_ghost_input();

        let old_leaves = hash_slots(&surface.old_slots);
        let new_leaves = hash_slots(&surface.new_slots);
        let old = evaluate_structural_frontier(&plan, &old_leaves, &proof.slot_siblings).unwrap();
        let new = evaluate_structural_frontier(&plan, &new_leaves, &proof.slot_siblings).unwrap();

        assert_eq!(batch.old_root, old.root);
        assert_eq!(batch.new_root, new.root);
        assert_eq!(batch.live_combines_per_root, live);
        assert_eq!(claims.len(), 2 * capacity);
        for (ordinal, expected) in old.combines.iter().enumerate() {
            assert_eq!(claims[ordinal].expected_digest, digest_to_fields(*expected));
        }
        assert!(claims[live..capacity].iter().all(|claim| **claim == ghost));
        for (ordinal, expected) in new.combines.iter().enumerate() {
            assert_eq!(
                claims[capacity + ordinal].expected_digest,
                digest_to_fields(*expected)
            );
        }
        assert!(claims[capacity + live..2 * capacity]
            .iter()
            .all(|claim| **claim == ghost));

        assert_eq!(
            structural_node_value(
                plan.root_ref(),
                &old_leaves,
                &proof.slot_siblings,
                &old.combines,
            ),
            batch.old_root
        );
        assert_eq!(
            structural_node_value(
                plan.root_ref(),
                &new_leaves,
                &proof.slot_siblings,
                &new.combines,
            ),
            batch.new_root
        );

        let params = exact_state_structural_hash_params();
        assert_eq!(params.domain_tag, TAG_EXSTNOD);
        assert_eq!(params.n_fields, 4);
        assert_eq!(
            params.relation_tag,
            0x4558_5354_4E4F_445F_4649_5848_4153_4805
        );
        assert_eq!(batch.chunks.len(), 1);
        let mut prover_channel = Poseidon2bChannel::new();
        let (hash_proof, expected_reductions) =
            prove_fixed_field_hash_killshot(params, &batch.chunks[0], &mut prover_channel);
        let mut verifier_channel = Poseidon2bChannel::new();
        let reductions = verify_fixed_field_hash_killshot(
            params,
            &hash_proof,
            &batch.chunks[0],
            &mut verifier_channel,
        )
        .expect("structural fixed-field proof verifies");
        assert_eq!(reductions, expected_reductions);
        assert!(discharge_fixed_field_hash_reductions_native(
            params,
            &batch.chunks[0],
            &reductions,
        ));
    }

    #[test]
    fn structural_hash_chunk_plans_are_class_fixed_and_m23_bounded() {
        let cases: &[(usize, &[usize])] = &[
            (2_152, &[4_304]),
            (7_374, &[8_192, 6_556]),
            (12_045, &[8_192, 8_192, 7_706]),
            (23_998, &[8_192, 8_192, 8_192, 8_192, 8_192, 7_036]),
        ];
        for &(capacity, expected_chunks) in cases {
            let plan = exact_state_structural_hash_chunk_plan(capacity).unwrap();
            assert_eq!(plan.combine_capacity_per_root, capacity);
            assert_eq!(plan.total_claims, 2 * capacity);
            assert_eq!(plan.chunk_lengths, expected_chunks);
            assert_eq!(plan.chunk_lengths.iter().sum::<usize>(), 2 * capacity);
            assert!(plan
                .chunk_lengths
                .iter()
                .all(|&len| len <= MAX_EXACT_STRUCTURAL_HASH_CLAIMS_PER_PROOF));
            // Four fields means two permutation slots per claim.  At most
            // 16,384 slots require 14 slot bits plus 7 round and 2 lane bits.
            assert!(plan
                .chunk_lengths
                .iter()
                .all(|&len| noid_gkr::block_spine::num_vars_for(2 * len) <= 23));
        }

        assert_eq!(
            exact_state_structural_hash_chunk_plan(0),
            Err(
                ExactStateTransitionError::StructuralCombineCapacityExceeded {
                    required: 1,
                    capacity: 0,
                }
            )
        );
        assert_eq!(
            exact_state_structural_hash_chunk_plan(MAX_EXACT_FRONTIER_COMBINES + 1),
            Err(
                ExactStateTransitionError::StructuralCombineCapacityTooLarge {
                    capacity: MAX_EXACT_FRONTIER_COMBINES + 1,
                    maximum: MAX_EXACT_FRONTIER_COMBINES,
                }
            )
        );
    }

    #[test]
    fn structural_hash_derivation_rejects_an_undersized_class_capacity() {
        let (surface, inputs, proof) = fixture(false);
        let required =
            derive_structural_frontier_plan(&surface.touched_indices, inputs.child_log_slots)
                .unwrap()
                .combines()
                .len();
        assert_eq!(
            derive_exact_state_structural_hash_batch_inputs(
                &inputs,
                &surface,
                &proof,
                required - 1,
            ),
            Err(
                ExactStateTransitionError::StructuralCombineCapacityExceeded {
                    required,
                    capacity: required - 1,
                }
            )
        );
    }

    #[test]
    fn root_depth_and_grow_zero_sibling_tamper_reject() {
        let (surface, inputs, proof) = fixture(false);

        let mut bad_parent = inputs.clone();
        bad_parent.parent_state_root[0] ^= 1;
        assert_eq!(
            verify_exact_state_transition(&bad_parent, &surface, &proof),
            Err(ExactStateTransitionError::ParentRootMismatch)
        );

        let mut bad_child = inputs.clone();
        bad_child.child_state_root[0] ^= 1;
        assert_eq!(
            verify_exact_state_transition(&bad_child, &surface, &proof),
            Err(ExactStateTransitionError::ChildRootMismatch)
        );

        let mut bad_depth = inputs;
        bad_depth.child_log_slots += 2;
        assert_eq!(
            verify_exact_state_transition(&bad_depth, &surface, &proof),
            Err(ExactStateTransitionError::InvalidLogSlots)
        );

        let (grow_surface, grow_inputs, mut grow_proof) = fixture(true);
        let last = grow_proof
            .slot_siblings
            .last_mut()
            .expect("a grow proof carries the top zero sibling");
        last[0] ^= 1;
        assert!(verify_exact_state_transition(&grow_inputs, &grow_surface, &grow_proof).is_err());
    }

    #[test]
    fn sibling_only_proof_serializes_under_cap() {
        let (surface, _, proof) = fixture(false);
        assert!(!surface.touched_indices.is_empty());
        let bytes = bincode::serialize(&proof).unwrap();
        assert!(bytes.len() <= MAX_EXACT_STATE_PROOF_BYTES);
        assert_eq!(proof.byte_len(), proof.slot_siblings.len() * 32);
    }

    #[test]
    fn production_frontier_uses_segment_aware_analytical_cap() {
        assert_eq!(MAX_EXACT_TOUCHED_SLOTS, 1_531);
        assert_eq!(MAX_EXACT_SLOT_SIBLINGS, 22_468);
        assert_eq!(MAX_EXACT_SLOT_SIBLING_BYTES, 718_976);
        assert_eq!(MAX_EXACT_STATE_PROOF_BYTES, 718_984);
    }

    #[test]
    fn proof_helpers_enforce_live_and_segment_caps_before_frontier_work() {
        let cache = SparseMerkleCache::new(32).unwrap();
        let oversized = ExactActionSurface {
            actions: Vec::new(),
            touched_indices: (0..=MAX_EXACT_TOUCHED_SLOTS as u32).collect(),
            old_slots: vec![SlotValue::EMPTY; MAX_EXACT_TOUCHED_SLOTS + 1],
            new_slots: vec![SlotValue::EMPTY; MAX_EXACT_TOUCHED_SLOTS + 1],
            spends: 0,
            mints: 0,
        };
        assert_eq!(
            build_exact_state_transition_proof(&cache, &oversized),
            Err(ExactStateTransitionError::TooManyTouchedSlots {
                actual: 1_532,
                maximum: 1_531,
            })
        );

        let dispersed: Vec<_> = (0..=noid_chain::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS)
            .map(|segment| (segment as u32) << noid_chain::consensus::params::LOG_SEGMENT_SIZE)
            .collect();
        let too_many_segments = ExactActionSurface {
            actions: Vec::new(),
            old_slots: vec![SlotValue::EMPTY; dispersed.len()],
            new_slots: vec![SlotValue::EMPTY; dispersed.len()],
            touched_indices: dispersed,
            spends: 0,
            mints: 0,
        };
        assert_eq!(
            build_exact_state_transition_proof(&cache, &too_many_segments),
            Err(ExactStateTransitionError::TooManyTouchedSegments {
                actual: 257,
                maximum: 256,
            })
        );

        let mut too_many_spends = surface(sv(10, 100), sv(7, 200));
        too_many_spends.spends = 1_021;
        assert_eq!(
            build_exact_state_transition_proof(&cache, &too_many_spends),
            Err(ExactStateTransitionError::TooManySpends {
                actual: 1_021,
                maximum: 1_020,
            })
        );

        let mut too_many_mints = surface(sv(10, 100), sv(7, 200));
        too_many_mints.mints = 512;
        assert_eq!(
            build_exact_state_transition_proof(&cache, &too_many_mints),
            Err(ExactStateTransitionError::TooManyMints {
                actual: 512,
                maximum: 511,
            })
        );
    }

    #[test]
    fn empty_native_transition_preserves_equal_or_grown_root() {
        let empty = exact_action_surface_from_surface(StateDeltaActionSurface {
            actions: Vec::new(),
            spends: 0,
            mints: 0,
        });
        let parent = [0x41u8; 32];
        for grow in [false, true] {
            let parent_log = 4u32;
            let child_log = parent_log + u32::from(grow);
            let child = if grow {
                let zeros = zero_slot_roots(parent_log as usize);
                state_node_hash(parent, zeros[parent_log as usize])
            } else {
                parent
            };
            let inputs = ExactStateTransitionInputs {
                parent_state_root: parent,
                parent_log_slots: parent_log,
                child_state_root: child,
                child_log_slots: child_log,
                parent_active_slot_count: 7,
                parent_alloc_counter: 11,
            };
            let verified =
                VerifiedStateTransition::from_verified_no_spend_native(&inputs, &empty, child)
                    .unwrap();
            assert_eq!(verified.child_state_root(), child);
            assert!(verified.slot_updates().is_empty());
            assert_eq!(verified.active_slot_count(), 7);
            assert_eq!(verified.alloc_counter(), 11);
        }
    }
}
