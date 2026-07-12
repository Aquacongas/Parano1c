// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Proof-facing verifier for accepted-block certificate batch components.
//!
//! `noid_block` owns block production and retained native replay. This module
//! owns the dependency-clean verifier language that the final O(1) recursive
//! checkpoint backend must prove after `noid_block` has replayed existing
//! `BlockProof`/`BlockAuthSidecar` bytes and reduced them into canonical proof
//! components. This module does not deserialize block bodies or replace the
//! production block verifier in `noid_block`.

use noid_chain::{
    exact_state_hash::{slot_leaf_hash, StateHash},
    sparse_merkle::{
        derive_structural_frontier_plan, evaluate_structural_frontier,
        expand_multiproof_segmented_updates, SegmentedSequentialMerkleUpdates, SparseMerkleError,
        StructuralFrontierEvaluation, StructuralFrontierPlan, StructuralNodeRef,
    },
    SlotValue,
};
use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_gkr::{
    discharge_accepted_claim_hash_reductions_native, discharge_batched_merkle_reductions_native,
    discharge_batched_slot_leaf_reductions_native, discharge_block_spine_reductions_native,
    discharge_fixed_field_hash_reductions_native, reconstruct_slot_states,
    verify_accepted_claim_hash_killshot, verify_batched_merkle_killshot,
    verify_batched_slot_leaf_killshot, verify_block_spine_killshot,
    verify_fixed_field_hash_killshot, AcceptedClaimHashInputs, AcceptedClaimHashProofKillShot,
    BatchedMerkleProofKillShot, BatchedSlotLeafProofKillShot, BlockSpineProof,
    FixedFieldHashInputs, FixedFieldHashParams, FixedFieldHashProofKillShot, MerkleCircuit,
    MerklePathInputs, OwnerAuthPublicInputs, SlotLeafInputs, SpineCircuit, SpineInputs,
    VerifiedAuthorizationBatch,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::TAG_EXSTNOD;
use rayon::prelude::*;

use crate::accepted_batch::{
    verify_accepted_claim_batch_with_header_trace, AcceptedClaimBatchError,
    AcceptedClaimBatchOutput, AcceptedClaimBatchWitness,
};
use crate::accumulator::ChainAccumulator;
use crate::block_certificate::{
    accepted_block_certificate_chain_claim, AcceptedBlockCertificateStatement,
};
use crate::checkpoint::{
    verify_checkpoint_poseidon, CheckpointPoseidonError, CheckpointPoseidonProof,
};
use crate::header_integer::HeaderIntegerBatchTrace;
use crate::pow_header::RecursiveConsensusState;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizationComponentInput {
    pub block_index: usize,
    pub tx_index: usize,
    pub tx_body_hash: [Block128; 2],
    /// Transitional canonical-body metadata. C' pins this byte to the
    /// transaction validity bitmap; it is deliberately not OwnerAuth public.
    pub live_input_count: u8,
    pub public: OwnerAuthPublicInputs,
}

fn authorization_component_input_shape_ok(input: &AuthorizationComponentInput) -> bool {
    input.public.layout == noid_gkr::OwnerAuthLayout::FIXED
        && (1..=noid_gkr::MAX_AUTHORIZATION_LIVE_INPUTS).contains(&input.live_input_count)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExactStateKillShotInputs {
    pub slot_leaves: Vec<SlotLeafInputs>,
    pub state_paths: Vec<MerklePathInputs>,
}

/// Sibling-only exact-state carrier with verifier-derived Merkle topology.
///
/// `live_sibling_digests` contains exactly the live structural frontier in the
/// canonical order derived from `touched_indices` and `active_depth`.  It is
/// deliberately not padded: an all-zero digest is valid live data and is not
/// interpreted as a PAD marker here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExactStateStructuralFrontierInputs {
    pub touched_indices: Vec<u32>,
    pub active_depth: u32,
    pub old_slot_leaves: Vec<SlotLeafInputs>,
    pub new_slot_leaves: Vec<SlotLeafInputs>,
    pub live_sibling_digests: Vec<StateHash>,
    /// Old-root parents in verifier-derived `plan.combines()` order.
    pub old_combine_digests: Vec<StateHash>,
    /// New-root parents in the same verifier-derived order.
    pub new_combine_digests: Vec<StateHash>,
    pub old_root: StateHash,
    pub new_root: StateHash,
}

/// Verifier-owned topology and hashes materialized from a structural frontier.
///
/// Returning the plan keeps subsequent proof construction independent of any
/// witness-supplied coordinates or path directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExactStateStructuralFrontier {
    pub plan: StructuralFrontierPlan,
    pub old_evaluation: StructuralFrontierEvaluation,
    pub new_evaluation: StructuralFrontierEvaluation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateStructuralFrontierError {
    SlotLeafCountMismatch {
        touched: usize,
        old: usize,
        new: usize,
    },
    OldSlotLeafMismatch {
        index: usize,
    },
    NewSlotLeafMismatch {
        index: usize,
    },
    CombineDigestCountMismatch {
        expected: usize,
        old: usize,
        new: usize,
    },
    OldCombineDigestMismatch {
        index: usize,
    },
    NewCombineDigestMismatch {
        index: usize,
    },
    OldRootRefMismatch,
    NewRootRefMismatch,
    OldRootMismatch,
    NewRootMismatch,
    SparseMerkle(SparseMerkleError),
}

impl From<SparseMerkleError> for ExactStateStructuralFrontierError {
    fn from(source: SparseMerkleError) -> Self {
        Self::SparseMerkle(source)
    }
}

/// Validate a sibling-only exact-state carrier and derive its canonical plan.
///
/// This native boundary intentionally recomputes the slot-leaf hashes as well
/// as both roots.  A future proof backend may discharge the leaf hashes and
/// structural combines algebraically, while preserving this exact public
/// carrier and verifier-derived topology.
pub fn verify_exact_state_structural_frontier(
    inputs: &ExactStateStructuralFrontierInputs,
) -> Result<VerifiedExactStateStructuralFrontier, ExactStateStructuralFrontierError> {
    let touched = inputs.touched_indices.len();
    if inputs.old_slot_leaves.len() != touched || inputs.new_slot_leaves.len() != touched {
        return Err(ExactStateStructuralFrontierError::SlotLeafCountMismatch {
            touched,
            old: inputs.old_slot_leaves.len(),
            new: inputs.new_slot_leaves.len(),
        });
    }

    let plan = derive_structural_frontier_plan(&inputs.touched_indices, inputs.active_depth)?;
    validate_structural_combine_digest_lengths(inputs, plan.combines().len())?;
    let old_leaves = validated_slot_leaf_hashes(&inputs.old_slot_leaves, |index| {
        ExactStateStructuralFrontierError::OldSlotLeafMismatch { index }
    })?;
    let new_leaves = validated_slot_leaf_hashes(&inputs.new_slot_leaves, |index| {
        ExactStateStructuralFrontierError::NewSlotLeafMismatch { index }
    })?;
    let old_evaluation =
        evaluate_structural_frontier(&plan, &old_leaves, &inputs.live_sibling_digests)?;
    if let Some(index) =
        first_digest_mismatch(&inputs.old_combine_digests, &old_evaluation.combines)
    {
        return Err(ExactStateStructuralFrontierError::OldCombineDigestMismatch { index });
    }
    if old_evaluation.root != inputs.old_root {
        return Err(ExactStateStructuralFrontierError::OldRootMismatch);
    }
    let new_evaluation =
        evaluate_structural_frontier(&plan, &new_leaves, &inputs.live_sibling_digests)?;
    if let Some(index) =
        first_digest_mismatch(&inputs.new_combine_digests, &new_evaluation.combines)
    {
        return Err(ExactStateStructuralFrontierError::NewCombineDigestMismatch { index });
    }
    if new_evaluation.root != inputs.new_root {
        return Err(ExactStateStructuralFrontierError::NewRootMismatch);
    }

    Ok(VerifiedExactStateStructuralFrontier {
        plan,
        old_evaluation,
        new_evaluation,
    })
}

/// Derive the fixed-shape-friendly sequential update projection of an
/// authoritative sibling-only carrier.
///
/// This is not another proof format. The verifier first performs the ordinary
/// canonical-frontier audit above, then deterministically projects the same
/// leaves and sibling vector into local slot updates and distinct-segment
/// updates. Each step uses one sibling path for both its before and after
/// roots, and the steps chain, so the outer trace can delete independently
/// supplied legacy old/new paths without weakening update binding.
pub fn derive_exact_state_segmented_updates(
    inputs: &ExactStateStructuralFrontierInputs,
    log_segment_size: u32,
) -> Result<SegmentedSequentialMerkleUpdates, ExactStateStructuralFrontierError> {
    verify_exact_state_structural_frontier(inputs)?;
    let old_leaves = inputs
        .old_slot_leaves
        .iter()
        .map(|leaf| fields_to_digest(leaf.expected_leaf))
        .collect::<Vec<_>>();
    let new_leaves = inputs
        .new_slot_leaves
        .iter()
        .map(|leaf| fields_to_digest(leaf.expected_leaf))
        .collect::<Vec<_>>();
    Ok(expand_multiproof_segmented_updates(
        &inputs.touched_indices,
        &old_leaves,
        &new_leaves,
        &inputs.live_sibling_digests,
        inputs.active_depth,
        log_segment_size,
    )?)
}

fn validated_slot_leaf_hashes(
    inputs: &[SlotLeafInputs],
    mismatch: impl Fn(usize) -> ExactStateStructuralFrontierError,
) -> Result<Vec<StateHash>, ExactStateStructuralFrontierError> {
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let digest = slot_leaf_hash(SlotValue {
                value: input.packed_value,
                owner_hi: input.owner_hi,
                owner_lo: input.owner_lo,
            });
            if fields_to_digest(input.expected_leaf) != digest {
                return Err(mismatch(index));
            }
            Ok(digest)
        })
        .collect()
}

fn validate_structural_combine_digest_lengths(
    inputs: &ExactStateStructuralFrontierInputs,
    expected: usize,
) -> Result<(), ExactStateStructuralFrontierError> {
    if inputs.old_combine_digests.len() != expected || inputs.new_combine_digests.len() != expected
    {
        return Err(
            ExactStateStructuralFrontierError::CombineDigestCountMismatch {
                expected,
                old: inputs.old_combine_digests.len(),
                new: inputs.new_combine_digests.len(),
            },
        );
    }
    Ok(())
}

fn first_digest_mismatch(left: &[StateHash], right: &[StateHash]) -> Option<usize> {
    left.iter()
        .zip(right.iter())
        .position(|(left, right)| left != right)
}

fn fields_to_digest(fields: [Block128; 2]) -> StateHash {
    let mut digest = [0u8; 32];
    digest[..16].copy_from_slice(&fields[0].0.to_le_bytes());
    digest[16..].copy_from_slice(&fields[1].0.to_le_bytes());
    digest
}

/// Maximum live structural EXSTNOD claims carried by one retained proof.
///
/// Each claim consumes two Poseidon permutations.  The 8,192-claim bound
/// therefore keeps every retained fixed-field hash proof at 16,384 live
/// permutation slots while avoiding any per-leaf path materialization.
pub const EXACT_STATE_STRUCTURAL_HASH_CHUNK_SIZE: usize = 8_192;

/// Fixed transcript marker for one independently verifiable structural chunk.
pub const EXACT_STATE_STRUCTURAL_CHUNK_TRANSCRIPT_TAG: u128 =
    0x4558_5354_4348_4E4B_0000_0000_0000_0001; // "EXSTCHNK" || v1

/// Deterministically seed one structural chunk transcript.
pub fn exact_state_structural_chunk_channel(
    chunk_index: usize,
    total_chunks: usize,
) -> Poseidon2bChannel {
    assert!(
        chunk_index < total_chunks,
        "structural chunk index in range"
    );
    let mut channel = Poseidon2bChannel::new();
    channel.absorb(Block128::from(EXACT_STATE_STRUCTURAL_CHUNK_TRANSCRIPT_TAG));
    channel.absorb(Block128::from(chunk_index as u128));
    channel.absorb(Block128::from(total_chunks as u128));
    channel
}

/// Bounded execution-policy lane count shared by prover and verifier.
///
/// The default is one. Values above the number of chunks are capped, so a
/// malformed environment cannot create unbounded parallel proof allocation.
pub fn exact_state_structural_proof_lanes(total_chunks: usize) -> usize {
    if total_chunks == 0 {
        return 0;
    }
    let requested = std::env::var("NOID_STRUCTURAL_PROOF_LANES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value != 0)
        .unwrap_or(1);
    requested.min(total_chunks)
}

/// The exact two-child EXSTNOD schedule used by structural frontier combines.
pub fn exact_state_structural_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(TAG_EXSTNOD, 4)
        .expect("four fields are a valid fixed EXSTNOD schedule")
}

/// Derive the canonical live structural hash chunks from a sibling-only
/// carrier.  The transcript order is every old-root combine followed by every
/// new-root combine, preserving the verifier-derived plan order in each half.
/// No class ghosts are retained here; fixed-class padding belongs to the outer
/// trace, not to the native retained component proof.
pub fn derive_exact_state_structural_hash_chunks(
    inputs: &ExactStateStructuralFrontierInputs,
) -> Result<Vec<Vec<FixedFieldHashInputs>>, ExactStateStructuralFrontierError> {
    verify_exact_state_structural_frontier(inputs)?;
    derive_exact_state_structural_hash_chunks_without_hashing(inputs)
}

/// Derive structural hash statements from a supplied DAG without evaluating
/// any hash natively.
///
/// Sound callers must verify the returned statements with the slot-leaf and
/// fixed-field hash proofs. This function validates canonical plan shape,
/// source-vector lengths, and final root references; the proof/discharge then
/// establishes every child-to-parent hash equation.
pub fn derive_exact_state_structural_hash_chunks_without_hashing(
    inputs: &ExactStateStructuralFrontierInputs,
) -> Result<Vec<Vec<FixedFieldHashInputs>>, ExactStateStructuralFrontierError> {
    let touched = inputs.touched_indices.len();
    if inputs.old_slot_leaves.len() != touched || inputs.new_slot_leaves.len() != touched {
        return Err(ExactStateStructuralFrontierError::SlotLeafCountMismatch {
            touched,
            old: inputs.old_slot_leaves.len(),
            new: inputs.new_slot_leaves.len(),
        });
    }
    let plan = derive_structural_frontier_plan(&inputs.touched_indices, inputs.active_depth)?;
    if inputs.live_sibling_digests.len() != plan.frontier_positions().len() {
        return Err(ExactStateStructuralFrontierError::SparseMerkle(
            SparseMerkleError::ProofLengthMismatch {
                expected: plan.frontier_positions().len(),
                actual: inputs.live_sibling_digests.len(),
            },
        ));
    }
    validate_structural_combine_digest_lengths(inputs, plan.combines().len())?;
    let old_leaves = inputs
        .old_slot_leaves
        .iter()
        .map(|leaf| fields_to_digest(leaf.expected_leaf))
        .collect::<Vec<_>>();
    let new_leaves = inputs
        .new_slot_leaves
        .iter()
        .map(|leaf| fields_to_digest(leaf.expected_leaf))
        .collect::<Vec<_>>();
    if structural_node_digest(
        plan.root_ref(),
        &old_leaves,
        &inputs.live_sibling_digests,
        &inputs.old_combine_digests,
    ) != inputs.old_root
    {
        return Err(ExactStateStructuralFrontierError::OldRootRefMismatch);
    }
    if structural_node_digest(
        plan.root_ref(),
        &new_leaves,
        &inputs.live_sibling_digests,
        &inputs.new_combine_digests,
    ) != inputs.new_root
    {
        return Err(ExactStateStructuralFrontierError::NewRootRefMismatch);
    }
    let mut claims = structural_hash_inputs_for_root(
        &plan,
        &old_leaves,
        &inputs.live_sibling_digests,
        &inputs.old_combine_digests,
    );
    claims.extend(structural_hash_inputs_for_root(
        &plan,
        &new_leaves,
        &inputs.live_sibling_digests,
        &inputs.new_combine_digests,
    ));
    Ok(claims
        .chunks(EXACT_STATE_STRUCTURAL_HASH_CHUNK_SIZE)
        .map(<[FixedFieldHashInputs]>::to_vec)
        .collect())
}

fn structural_hash_inputs_for_root(
    plan: &StructuralFrontierPlan,
    leaves: &[StateHash],
    siblings: &[StateHash],
    combines: &[StateHash],
) -> Vec<FixedFieldHashInputs> {
    plan.combines()
        .iter()
        .enumerate()
        .map(|(ordinal, combine)| {
            let left = structural_node_digest(combine.left, leaves, siblings, combines);
            let right = structural_node_digest(combine.right, leaves, siblings, combines);
            FixedFieldHashInputs {
                fields: vec![
                    digest_to_fields(left)[0],
                    digest_to_fields(left)[1],
                    digest_to_fields(right)[0],
                    digest_to_fields(right)[1],
                ],
                expected_digest: digest_to_fields(combines[ordinal]),
            }
        })
        .collect()
}

fn structural_node_digest(
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

fn digest_to_fields(digest: StateHash) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExactStateKillShotProof {
    pub slot_leaves: BatchedSlotLeafProofKillShot,
    /// Depth-32-safe chunks keep the transitional full-path prover below an
    /// m24+ monolith while the outer trace still consumes legacy paths.
    /// Small transitional proofs may populate it for the not-yet-migrated
    /// inline outer trace. It is never an alternative to structural retained
    /// verification: when present, the component verifier checks both.
    pub state_paths: Vec<BatchedMerkleProofKillShot>,
    /// Live old-root then new-root EXSTNOD combines over the sibling-only
    /// verifier-derived structural frontier.
    pub structural_hashes: Vec<FixedFieldHashProofKillShot>,
}

/// At maximum depth each path contributes 64 permutation slots, so 256 paths
/// cap every transitional Merkle batch at 16,384 live slots.
pub const EXACT_STATE_MERKLE_PATH_CHUNK_SIZE: usize = 256;

impl ExactStateKillShotProof {
    pub fn byte_len(&self, inputs: &ExactStateKillShotInputs) -> usize {
        self.slot_leaves.byte_len()
            + self
                .state_paths
                .iter()
                .zip(
                    inputs
                        .state_paths
                        .chunks(EXACT_STATE_MERKLE_PATH_CHUNK_SIZE),
                )
                .map(|(proof, paths)| proof.byte_len(paths))
                .sum::<usize>()
            + self
                .structural_hashes
                .iter()
                .map(FixedFieldHashProofKillShot::byte_len)
                .sum::<usize>()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockBatchComponentInputs {
    pub accepted_claim_witness: AcceptedClaimBatchWitness,
    pub accepted_block_certificate_statements: Vec<AcceptedBlockCertificateStatement>,
    pub accepted_claim_hash_inputs: Vec<AcceptedClaimHashInputs>,
    pub tx_body_inputs: Vec<SpineInputs>,
    pub tx_body_hashes: Vec<[Block128; 2]>,
    pub tx_root_inputs: Vec<MerklePathInputs>,
    pub header_integer_trace: HeaderIntegerBatchTrace,
    pub authorization_inputs: Vec<AuthorizationComponentInput>,
    /// Transitional expanded paths consumed only by the not-yet-migrated
    /// outer trace. Native retained verification does not trust or verify
    /// these paths once the sibling-only structural carrier is present.
    pub exact_state_killshot_inputs: Vec<ExactStateKillShotInputs>,
    /// Authoritative sibling-only exact-state inputs for retained native
    /// verification and retained structural hash proofs.
    pub exact_state_structural_inputs: Vec<ExactStateStructuralFrontierInputs>,
    pub authorization_totals: VerifiedAuthorizationBatch,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockBatchComponentProof {
    pub accepted_claim_hash: AcceptedClaimHashProofKillShot,
    pub tx_body: Option<BlockSpineProof>,
    pub tx_root: Option<BatchedMerkleProofKillShot>,
    pub checkpoint_poseidon: CheckpointPoseidonProof,
    pub exact_state: Vec<ExactStateKillShotProof>,
}

impl AcceptedBlockBatchComponentProof {
    pub fn byte_len(&self, inputs: &AcceptedBlockBatchComponentInputs) -> usize {
        self.accepted_claim_hash.byte_len()
            + self.tx_body.as_ref().map_or(0, BlockSpineProof::byte_len)
            + self
                .tx_root
                .as_ref()
                .map_or(0, |proof| proof.byte_len(&inputs.tx_root_inputs))
            + self.checkpoint_poseidon.byte_len()
            + self
                .exact_state
                .iter()
                .zip(inputs.exact_state_killshot_inputs.iter())
                .map(|(proof, inputs)| proof.byte_len(inputs))
                .sum::<usize>()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateKillShotError {
    EmptyDerivedInput,
    SlotLeafProofRejected,
    StateMerkleProofRejected,
    StructuralFrontier(ExactStateStructuralFrontierError),
    StructuralHashProofRejected,
    NonCanonicalLegacyPathProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockBatchComponentError {
    ComponentShapeMismatch,
    CertificateStatementMismatch {
        index: usize,
    },
    AcceptedClaimHashProofRejected,
    TxBodyHashProofRejected,
    TxRootProofRejected,
    AcceptedClaimBatch(AcceptedClaimBatchError),
    CheckpointPoseidon(CheckpointPoseidonError),
    ExactState {
        index: usize,
        source: ExactStateKillShotError,
    },
}

/// Verify the canonical component carrier consumed by the selected-ZK B255
/// Block relation.
///
/// Authorization proofs are not accepted by this DTO. This boundary binds
/// their canonical public statements and aggregate counts; the consuming B255
/// input owns and verifies the corresponding ZK authorization proofs exactly
/// once.
pub fn verify_accepted_block_batch_components(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<AcceptedClaimBatchOutput, AcceptedBlockBatchComponentError> {
    validate_component_shape(inputs, proof)?;
    validate_certificate_statement_component_shape(inputs)?;

    // All component verifications are independent, so run them as one parallel
    // join tree (mirroring the prover side in `noid_block`). Results are
    // unwrapped below in the same order the old sequential code checked them,
    // so error precedence is unchanged when several components fail at once.
    let (
        (claim_hash_result, tx_body_result),
        (
            (tx_root_result, authorization_result),
            (claim_batch_result, (checkpoint_result, exact_state_result)),
        ),
    ) = rayon::join(
        || {
            rayon::join(
                || verify_accepted_claim_hash_component(inputs, proof),
                || verify_tx_body_component(inputs, proof),
            )
        },
        || {
            rayon::join(
                || {
                    rayon::join(
                        || verify_tx_root_component(inputs, proof),
                        || verify_authorization_component_shape(inputs),
                    )
                },
                || {
                    rayon::join(
                        || {
                            verify_accepted_claim_batch_with_header_trace(
                                start_consensus,
                                start_accumulator,
                                &inputs.accepted_claim_witness,
                                &inputs.header_integer_trace,
                            )
                            .map_err(AcceptedBlockBatchComponentError::AcceptedClaimBatch)
                        },
                        || {
                            rayon::join(
                                || {
                                    verify_checkpoint_poseidon(
                                        &inputs.accepted_claim_witness,
                                        &proof.checkpoint_poseidon,
                                    )
                                    .map_err(AcceptedBlockBatchComponentError::CheckpointPoseidon)
                                },
                                || {
                                    inputs
                                        .exact_state_structural_inputs
                                        .par_iter()
                                        .zip(inputs.exact_state_killshot_inputs.par_iter())
                                        .zip(proof.exact_state.par_iter())
                                        .enumerate()
                                        .try_for_each(|(index, ((structural, legacy), proof))| {
                                            verify_exact_state_structural_killshot(
                                                structural, proof,
                                            )
                                            .and_then(|()| {
                                                if proof.state_paths.is_empty() {
                                                    Ok(())
                                                } else if legacy.state_paths.is_empty() {
                                                    Err(ExactStateKillShotError::NonCanonicalLegacyPathProof)
                                                } else {
                                                    verify_exact_state_killshot(legacy, proof)
                                                }
                                            })
                                            .map_err(
                                                |source| {
                                                    AcceptedBlockBatchComponentError::ExactState {
                                                        index,
                                                        source,
                                                    }
                                                },
                                            )
                                        })
                                },
                            )
                        },
                    )
                },
            )
        },
    );

    claim_hash_result?;
    tx_body_result?;
    tx_root_result?;
    authorization_result?;
    let accepted_claim_batch = claim_batch_result?;
    if accepted_claim_batch.accumulator != *end_accumulator {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    checkpoint_result?;
    exact_state_result?;

    Ok(accepted_claim_batch)
}

pub fn verify_exact_state_killshot(
    inputs: &ExactStateKillShotInputs,
    proof: &ExactStateKillShotProof,
) -> Result<(), ExactStateKillShotError> {
    validate_exact_state_inputs(inputs)?;

    let (slot_result, state_result) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            let reductions = verify_batched_slot_leaf_killshot(
                &proof.slot_leaves,
                &inputs.slot_leaves,
                &mut channel,
            )
            .ok_or(ExactStateKillShotError::SlotLeafProofRejected)?;
            if discharge_batched_slot_leaf_reductions_native(&inputs.slot_leaves, &reductions) {
                Ok(())
            } else {
                Err(ExactStateKillShotError::SlotLeafProofRejected)
            }
        },
        || {
            let circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
            let mut channel = Poseidon2bChannel::new();
            let expected_chunks = inputs
                .state_paths
                .len()
                .div_ceil(EXACT_STATE_MERKLE_PATH_CHUNK_SIZE);
            if proof.state_paths.len() != expected_chunks {
                return Err(ExactStateKillShotError::StateMerkleProofRejected);
            }
            for (path_chunk, chunk_proof) in inputs
                .state_paths
                .chunks(EXACT_STATE_MERKLE_PATH_CHUNK_SIZE)
                .zip(proof.state_paths.iter())
            {
                let reductions =
                    verify_batched_merkle_killshot(&circuit, chunk_proof, path_chunk, &mut channel)
                        .ok_or(ExactStateKillShotError::StateMerkleProofRejected)?;
                if !discharge_batched_merkle_reductions_native(&circuit, path_chunk, &reductions) {
                    return Err(ExactStateKillShotError::StateMerkleProofRejected);
                }
            }
            Ok(())
        },
    );
    slot_result?;
    state_result?;
    Ok(())
}

/// Verify the authoritative retained exact-state proof over the sibling-only
/// structural carrier.
///
/// The old/new slot leaves are hashed once, while the canonical verifier-
/// derived combine stream is proved in bounded fixed-field chunks. Optional
/// legacy paths are ignored here and, when present on an accepted component,
/// verified separately only for transitional inline-outer compatibility.
pub fn verify_exact_state_structural_killshot(
    inputs: &ExactStateStructuralFrontierInputs,
    proof: &ExactStateKillShotProof,
) -> Result<(), ExactStateKillShotError> {
    let mut slot_leaves =
        Vec::with_capacity(inputs.old_slot_leaves.len() + inputs.new_slot_leaves.len());
    slot_leaves.extend_from_slice(&inputs.old_slot_leaves);
    slot_leaves.extend_from_slice(&inputs.new_slot_leaves);
    let structural_chunks = derive_exact_state_structural_hash_chunks_without_hashing(inputs)
        .map_err(ExactStateKillShotError::StructuralFrontier)?;
    if slot_leaves.is_empty() || structural_chunks.is_empty() {
        return Err(ExactStateKillShotError::EmptyDerivedInput);
    }

    let (slot_result, structural_result) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            let reductions =
                verify_batched_slot_leaf_killshot(&proof.slot_leaves, &slot_leaves, &mut channel)
                    .ok_or(ExactStateKillShotError::SlotLeafProofRejected)?;
            if discharge_batched_slot_leaf_reductions_native(&slot_leaves, &reductions) {
                Ok(())
            } else {
                Err(ExactStateKillShotError::SlotLeafProofRejected)
            }
        },
        || {
            verify_exact_state_structural_hash_chunk_proofs(
                &structural_chunks,
                &proof.structural_hashes,
            )
        },
    );
    slot_result?;
    structural_result?;
    Ok(())
}

/// Verify independently domain-separated structural chunks with bounded,
/// lane-strided parallelism. Proof vector order remains canonical regardless
/// of the selected execution-policy lane count.
pub fn verify_exact_state_structural_hash_chunk_proofs(
    chunks: &[Vec<FixedFieldHashInputs>],
    proofs: &[FixedFieldHashProofKillShot],
) -> Result<(), ExactStateKillShotError> {
    if chunks.is_empty() || proofs.len() != chunks.len() {
        return Err(ExactStateKillShotError::StructuralHashProofRejected);
    }
    let total_chunks = chunks.len();
    let lanes = exact_state_structural_proof_lanes(total_chunks);
    let lane_results = (0..lanes)
        .into_par_iter()
        .map(|lane| {
            let params = exact_state_structural_hash_params();
            for chunk_index in (lane..total_chunks).step_by(lanes) {
                let mut channel = exact_state_structural_chunk_channel(chunk_index, total_chunks);
                let reductions = verify_fixed_field_hash_killshot(
                    params,
                    &proofs[chunk_index],
                    &chunks[chunk_index],
                    &mut channel,
                )
                .ok_or(ExactStateKillShotError::StructuralHashProofRejected)?;
                if !discharge_fixed_field_hash_reductions_native(
                    params,
                    &chunks[chunk_index],
                    &reductions,
                ) {
                    return Err(ExactStateKillShotError::StructuralHashProofRejected);
                }
            }
            Ok(())
        })
        .collect::<Vec<Result<(), ExactStateKillShotError>>>();
    for result in lane_results {
        result?;
    }
    Ok(())
}

fn validate_component_shape(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<(), AcceptedBlockBatchComponentError> {
    let block_count = inputs.accepted_claim_witness.headers.len();
    if inputs.exact_state_structural_inputs.len() != block_count
        || inputs.exact_state_structural_inputs.len() != proof.exact_state.len()
        || inputs.exact_state_killshot_inputs.len() != inputs.exact_state_structural_inputs.len()
        || inputs.accepted_claim_hash_inputs.len()
            != inputs.accepted_claim_witness.accepted_block_claims.len()
        || inputs.tx_body_inputs.len() != inputs.tx_body_hashes.len()
    {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    if inputs
        .authorization_inputs
        .iter()
        .any(|input| !authorization_component_input_shape_ok(input))
    {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    if inputs
        .exact_state_killshot_inputs
        .iter()
        .zip(inputs.exact_state_structural_inputs.iter())
        .any(|(legacy, structural)| !legacy_exact_state_matches_structural(legacy, structural))
    {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    Ok(())
}

fn legacy_exact_state_matches_structural(
    legacy: &ExactStateKillShotInputs,
    structural: &ExactStateStructuralFrontierInputs,
) -> bool {
    let touched = structural.touched_indices.len();
    let Some(double_touched) = touched.checked_mul(2) else {
        return false;
    };
    if double_touched > EXACT_STATE_MERKLE_PATH_CHUNK_SIZE {
        return legacy.slot_leaves.is_empty() && legacy.state_paths.is_empty();
    }
    if legacy.slot_leaves.len() != double_touched
        || legacy.state_paths.len() != double_touched
        || legacy.slot_leaves[..touched] != structural.old_slot_leaves
        || legacy.slot_leaves[touched..] != structural.new_slot_leaves
    {
        return false;
    }
    legacy.state_paths.iter().enumerate().all(|(index, path)| {
        path.active_depth == structural.active_depth as usize
            && path.leaf == legacy.slot_leaves[index].expected_leaf
            && fields_to_digest(path.expected_root)
                == if index < touched {
                    structural.old_root
                } else {
                    structural.new_root
                }
    })
}

fn validate_certificate_statement_component_shape(
    inputs: &AcceptedBlockBatchComponentInputs,
) -> Result<(), AcceptedBlockBatchComponentError> {
    let headers = &inputs.accepted_claim_witness.headers;
    let claims = &inputs.accepted_claim_witness.accepted_block_claims;
    let statements = &inputs.accepted_block_certificate_statements;
    if statements.len() != headers.len() || statements.len() != claims.len() {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    for (index, ((statement, header_witness), chain_claim)) in statements
        .iter()
        .zip(headers.iter())
        .zip(claims.iter().copied())
        .enumerate()
    {
        if statement.block_id != header_witness.block_id
            || statement.height != header_witness.header.height
            || statement.child_state_root != header_witness.header.state_root
            || statement.tx_root != header_witness.header.tx_root
            || accepted_block_certificate_chain_claim(statement) != chain_claim
        {
            return Err(AcceptedBlockBatchComponentError::CertificateStatementMismatch { index });
        }
    }
    Ok(())
}

fn verify_accepted_claim_hash_component(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<(), AcceptedBlockBatchComponentError> {
    for (input, claim) in inputs
        .accepted_claim_hash_inputs
        .iter()
        .zip(inputs.accepted_claim_witness.accepted_block_claims.iter())
    {
        if input.expected_claim != *claim {
            return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
        }
    }
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_accepted_claim_hash_killshot(
        &proof.accepted_claim_hash,
        &inputs.accepted_claim_hash_inputs,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentError::AcceptedClaimHashProofRejected)?;
    if discharge_accepted_claim_hash_reductions_native(
        &inputs.accepted_claim_hash_inputs,
        &reductions,
    ) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentError::AcceptedClaimHashProofRejected)
    }
}

fn verify_tx_body_component(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<(), AcceptedBlockBatchComponentError> {
    if inputs.tx_body_inputs.is_empty() {
        if proof.tx_body.is_some() {
            return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
        }
        return Ok(());
    }
    let tx_body_proof = proof
        .tx_body
        .as_ref()
        .ok_or(AcceptedBlockBatchComponentError::ComponentShapeMismatch)?;
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_block_spine_killshot(
        tx_body_proof,
        inputs.tx_body_inputs.len(),
        &inputs.tx_body_hashes,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentError::TxBodyHashProofRejected)?;
    let slot_state_ins = tx_body_slot_state_ins(&inputs.tx_body_inputs);
    if discharge_block_spine_reductions_native(
        inputs.tx_body_inputs.len(),
        &slot_state_ins,
        &reductions,
    ) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentError::TxBodyHashProofRejected)
    }
}

fn verify_tx_root_component(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<(), AcceptedBlockBatchComponentError> {
    if inputs.tx_root_inputs.is_empty() {
        if proof.tx_root.is_some() {
            return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
        }
        return Ok(());
    }
    let tx_root_proof = proof
        .tx_root
        .as_ref()
        .ok_or(AcceptedBlockBatchComponentError::ComponentShapeMismatch)?;
    let circuit = MerkleCircuit::build();
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_batched_merkle_killshot(
        &circuit,
        tx_root_proof,
        &inputs.tx_root_inputs,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentError::TxRootProofRejected)?;
    if discharge_batched_merkle_reductions_native(&circuit, &inputs.tx_root_inputs, &reductions) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentError::TxRootProofRejected)
    }
}

/// Bind the public authorization statement carrier to the totals consumed by
/// the selected ZK authorization region. The proofs themselves have a single
/// owner: the consuming B255 Block input.
fn verify_authorization_component_shape(
    inputs: &AcceptedBlockBatchComponentInputs,
) -> Result<(), AcceptedBlockBatchComponentError> {
    if !authorization_component_totals_match(
        &inputs.authorization_inputs,
        &inputs.authorization_totals,
    ) {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    Ok(())
}

fn authorization_component_totals_match(
    inputs: &[AuthorizationComponentInput],
    totals: &VerifiedAuthorizationBatch,
) -> bool {
    let Some(live_input_count_total) = inputs.iter().try_fold(0usize, |sum, input| {
        sum.checked_add(usize::from(input.live_input_count))
    }) else {
        return false;
    };
    inputs.len() == totals.user_tx_count && live_input_count_total == totals.live_input_count_total
}

fn validate_exact_state_inputs(
    inputs: &ExactStateKillShotInputs,
) -> Result<(), ExactStateKillShotError> {
    if inputs.slot_leaves.is_empty() || inputs.state_paths.is_empty() {
        return Err(ExactStateKillShotError::EmptyDerivedInput);
    }
    if inputs.slot_leaves.len() != inputs.state_paths.len() || inputs.state_paths.len() % 2 != 0 {
        return Err(ExactStateKillShotError::EmptyDerivedInput);
    }
    let half = inputs.state_paths.len() / 2;
    let depth = inputs.state_paths[0].active_depth;
    let old_root = inputs.state_paths[0].expected_root;
    let new_root = inputs.state_paths[half].expected_root;
    if inputs.state_paths.iter().enumerate().any(|(index, path)| {
        path.active_depth != depth
            || path.leaf != inputs.slot_leaves[index].expected_leaf
            || path.expected_root != if index < half { old_root } else { new_root }
    }) {
        return Err(ExactStateKillShotError::StateMerkleProofRejected);
    }
    Ok(())
}

fn tx_body_slot_state_ins(inputs: &[SpineInputs]) -> Vec<[Block128; 4]> {
    let circuit = SpineCircuit::build();
    let mut slot_state_ins = Vec::new();
    for input in inputs {
        slot_state_ins.extend(
            reconstruct_slot_states(&circuit, input)
                .iter()
                .map(|(state_in, _)| *state_in),
        );
    }
    slot_state_ins
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_to_fields(digest: StateHash) -> [Block128; 2] {
        [
            Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
            Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
        ]
    }

    fn structural_slot_leaf(seed: u128) -> SlotLeafInputs {
        let slot = SlotValue {
            value: Block128::from(seed),
            owner_hi: Block128::from(seed.wrapping_mul(17)),
            owner_lo: Block128::from(seed.wrapping_mul(29)),
        };
        SlotLeafInputs {
            packed_value: slot.value,
            owner_hi: slot.owner_hi,
            owner_lo: slot.owner_lo,
            expected_leaf: digest_to_fields(slot_leaf_hash(slot)),
        }
    }

    fn structural_frontier_fixture() -> ExactStateStructuralFrontierInputs {
        let touched_indices = vec![1, 2, 11];
        let active_depth = 4;
        let old_slot_leaves = (1..=3).map(structural_slot_leaf).collect::<Vec<_>>();
        let new_slot_leaves = (101..=103).map(structural_slot_leaf).collect::<Vec<_>>();
        let plan = derive_structural_frontier_plan(&touched_indices, active_depth).unwrap();
        let live_sibling_digests = (0..plan.frontier_positions().len())
            .map(|ordinal| {
                slot_leaf_hash(SlotValue {
                    value: Block128::from(1_000 + ordinal as u128),
                    owner_hi: Block128::from(2_000 + ordinal as u128),
                    owner_lo: Block128::from(3_000 + ordinal as u128),
                })
            })
            .collect::<Vec<_>>();
        let old_hashes = old_slot_leaves
            .iter()
            .map(|input| fields_to_digest(input.expected_leaf))
            .collect::<Vec<_>>();
        let new_hashes = new_slot_leaves
            .iter()
            .map(|input| fields_to_digest(input.expected_leaf))
            .collect::<Vec<_>>();
        let old_evaluation =
            evaluate_structural_frontier(&plan, &old_hashes, &live_sibling_digests).unwrap();
        let new_evaluation =
            evaluate_structural_frontier(&plan, &new_hashes, &live_sibling_digests).unwrap();
        ExactStateStructuralFrontierInputs {
            touched_indices,
            active_depth,
            old_slot_leaves,
            new_slot_leaves,
            live_sibling_digests,
            old_combine_digests: old_evaluation.combines,
            new_combine_digests: new_evaluation.combines,
            old_root: old_evaluation.root,
            new_root: new_evaluation.root,
        }
    }

    fn structural_parity_fixture(touched: usize) -> ExactStateStructuralFrontierInputs {
        ExactStateStructuralFrontierInputs {
            touched_indices: (0..touched as u32).collect(),
            active_depth: 8,
            old_slot_leaves: (0..touched)
                .map(|index| structural_slot_leaf(index as u128 + 1))
                .collect(),
            new_slot_leaves: (0..touched)
                .map(|index| structural_slot_leaf(index as u128 + 10_001))
                .collect(),
            live_sibling_digests: Vec::new(),
            old_combine_digests: Vec::new(),
            new_combine_digests: Vec::new(),
            old_root: [0x11; 32],
            new_root: [0x22; 32],
        }
    }

    fn matching_legacy_inputs(
        structural: &ExactStateStructuralFrontierInputs,
    ) -> ExactStateKillShotInputs {
        let touched = structural.touched_indices.len();
        let mut slot_leaves = Vec::with_capacity(2 * touched);
        slot_leaves.extend(structural.old_slot_leaves.iter().cloned());
        slot_leaves.extend(structural.new_slot_leaves.iter().cloned());
        let state_paths = slot_leaves
            .iter()
            .enumerate()
            .map(|(index, leaf)| {
                let mut path = MerklePathInputs::zero();
                path.leaf = leaf.expected_leaf;
                path.expected_root = digest_to_fields(if index < touched {
                    structural.old_root
                } else {
                    structural.new_root
                });
                path.active_depth = structural.active_depth as usize;
                path
            })
            .collect();
        ExactStateKillShotInputs {
            slot_leaves,
            state_paths,
        }
    }

    fn authorization_component_input() -> AuthorizationComponentInput {
        AuthorizationComponentInput {
            block_index: 0,
            tx_index: 0,
            tx_body_hash: [Block128::from(7u128), Block128::from(8u128)],
            live_input_count: 1,
            public: OwnerAuthPublicInputs::new(
                [Block128::from(7u128), Block128::from(8u128)],
                [Block128::from(9u128), Block128::from(10u128)],
            ),
        }
    }

    #[test]
    fn authorization_component_boundary_rejects_bad_live_count() {
        let valid = authorization_component_input();
        assert!(authorization_component_input_shape_ok(&valid));

        for count in [0, noid_gkr::MAX_AUTHORIZATION_LIVE_INPUTS + 1] {
            let mut bad_count = valid.clone();
            bad_count.live_input_count = count;
            assert!(!authorization_component_input_shape_ok(&bad_count));
        }
    }

    #[test]
    fn authorization_component_totals_bind_selected_proof_cardinality() {
        let first = authorization_component_input();
        let mut second = first.clone();
        second.tx_index = 1;
        second.live_input_count = 2;
        let inputs = vec![first, second];
        let live_input_count_total = inputs
            .iter()
            .map(|input| usize::from(input.live_input_count))
            .sum::<usize>();

        assert!(authorization_component_totals_match(
            &inputs,
            &VerifiedAuthorizationBatch {
                user_tx_count: 2,
                live_input_count_total,
            },
        ));
        assert!(!authorization_component_totals_match(
            &inputs,
            &VerifiedAuthorizationBatch {
                user_tx_count: 1,
                live_input_count_total,
            },
        ));
        assert!(!authorization_component_totals_match(
            &inputs,
            &VerifiedAuthorizationBatch {
                user_tx_count: 2,
                live_input_count_total: 2,
            },
        ));
    }

    #[test]
    fn legacy_structural_parity_keeps_exact_256_path_boundary() {
        let structural = structural_parity_fixture(128);
        let legacy = matching_legacy_inputs(&structural);
        assert_eq!(legacy.state_paths.len(), EXACT_STATE_MERKLE_PATH_CHUNK_SIZE);
        assert!(legacy_exact_state_matches_structural(&legacy, &structural));

        let empty = ExactStateKillShotInputs {
            slot_leaves: Vec::new(),
            state_paths: Vec::new(),
        };
        assert!(!legacy_exact_state_matches_structural(&empty, &structural));
    }

    #[test]
    fn legacy_structural_parity_requires_empty_large_projection() {
        let structural = structural_parity_fixture(129);
        let empty = ExactStateKillShotInputs {
            slot_leaves: Vec::new(),
            state_paths: Vec::new(),
        };
        assert!(legacy_exact_state_matches_structural(&empty, &structural));

        let legacy = matching_legacy_inputs(&structural);
        assert_eq!(legacy.state_paths.len(), 258);
        assert!(!legacy_exact_state_matches_structural(&legacy, &structural));
    }

    #[test]
    fn structural_frontier_verifier_derives_plan_and_binds_both_roots() {
        let inputs = structural_frontier_fixture();
        let verified = verify_exact_state_structural_frontier(&inputs).unwrap();

        assert_eq!(verified.plan.touched_leaf_count(), 3);
        assert_eq!(
            verified.plan.frontier_positions().len(),
            inputs.live_sibling_digests.len()
        );
        assert_eq!(verified.old_evaluation.root, inputs.old_root);
        assert_eq!(verified.new_evaluation.root, inputs.new_root);
        assert_eq!(verified.old_evaluation.combines, inputs.old_combine_digests);
        assert_eq!(verified.new_evaluation.combines, inputs.new_combine_digests);
    }

    #[test]
    fn structural_carrier_projects_to_chained_segment_updates_without_legacy_paths() {
        let inputs = structural_frontier_fixture();
        let projected = derive_exact_state_segmented_updates(&inputs, 2).unwrap();

        assert_eq!(projected.local_depth, 2);
        assert_eq!(projected.upper_depth, 2);
        assert_eq!(projected.local_updates.len(), inputs.touched_indices.len());
        assert_eq!(
            projected
                .segment_updates
                .iter()
                .map(|update| update.index)
                .collect::<Vec<_>>(),
            [0, 2]
        );
        assert_eq!(
            projected.local_updates[0].root_after,
            projected.local_updates[1].root_before
        );
        assert_eq!(projected.segment_updates[0].root_before, inputs.old_root);
        assert_eq!(
            projected.segment_updates[0].root_after,
            projected.segment_updates[1].root_before
        );
        assert_eq!(projected.segment_updates[1].root_after, inputs.new_root);
    }

    #[test]
    fn non_hashing_structural_statement_matches_independently_audited_derivation() {
        let inputs = structural_frontier_fixture();
        let audited = derive_exact_state_structural_hash_chunks(&inputs).unwrap();
        let supplied = derive_exact_state_structural_hash_chunks_without_hashing(&inputs).unwrap();
        assert_eq!(supplied, audited);

        let mut changed_intermediate = inputs.clone();
        changed_intermediate.old_combine_digests[0][0] ^= 1;
        assert_eq!(
            verify_exact_state_structural_frontier(&changed_intermediate),
            Err(ExactStateStructuralFrontierError::OldCombineDigestMismatch { index: 0 })
        );
        assert_ne!(
            derive_exact_state_structural_hash_chunks_without_hashing(&changed_intermediate)
                .unwrap(),
            audited,
            "the fast path must expose a changed supplied DAG to the hash proof"
        );
    }

    #[test]
    fn structural_frontier_verifier_rejects_noncanonical_shape() {
        let mut bad_count = structural_frontier_fixture();
        bad_count.new_slot_leaves.pop();
        assert!(matches!(
            verify_exact_state_structural_frontier(&bad_count),
            Err(ExactStateStructuralFrontierError::SlotLeafCountMismatch {
                touched: 3,
                old: 3,
                new: 2
            })
        ));

        let mut unsorted = structural_frontier_fixture();
        unsorted.touched_indices.swap(0, 1);
        assert!(matches!(
            verify_exact_state_structural_frontier(&unsorted),
            Err(ExactStateStructuralFrontierError::SparseMerkle(
                SparseMerkleError::UnsortedIndices
            ))
        ));

        let mut short_frontier = structural_frontier_fixture();
        short_frontier.live_sibling_digests.pop();
        assert!(matches!(
            verify_exact_state_structural_frontier(&short_frontier),
            Err(ExactStateStructuralFrontierError::SparseMerkle(
                SparseMerkleError::ProofLengthMismatch { .. }
            ))
        ));

        let mut short_combines = structural_frontier_fixture();
        short_combines.old_combine_digests.pop();
        assert!(matches!(
            verify_exact_state_structural_frontier(&short_combines),
            Err(ExactStateStructuralFrontierError::CombineDigestCountMismatch { .. })
        ));
    }

    #[test]
    fn structural_frontier_verifier_rejects_leaf_and_root_tampering() {
        let mut bad_leaf = structural_frontier_fixture();
        bad_leaf.old_slot_leaves[1].expected_leaf[0] += Block128::from(1u128);
        assert_eq!(
            verify_exact_state_structural_frontier(&bad_leaf),
            Err(ExactStateStructuralFrontierError::OldSlotLeafMismatch { index: 1 })
        );

        let mut bad_root = structural_frontier_fixture();
        bad_root.new_root[0] ^= 1;
        assert_eq!(
            verify_exact_state_structural_frontier(&bad_root),
            Err(ExactStateStructuralFrontierError::NewRootMismatch)
        );
    }

    #[test]
    fn structural_frontier_accepts_zero_digest_as_live_sibling() {
        let old_slot_leaves = vec![structural_slot_leaf(7)];
        let new_slot_leaves = vec![structural_slot_leaf(8)];
        let touched_indices = vec![0];
        let active_depth = 1;
        let live_sibling_digests = vec![[0u8; 32]];
        let plan = derive_structural_frontier_plan(&touched_indices, active_depth).unwrap();
        let old_hash = fields_to_digest(old_slot_leaves[0].expected_leaf);
        let new_hash = fields_to_digest(new_slot_leaves[0].expected_leaf);
        let old_evaluation =
            evaluate_structural_frontier(&plan, &[old_hash], &live_sibling_digests).unwrap();
        let new_evaluation =
            evaluate_structural_frontier(&plan, &[new_hash], &live_sibling_digests).unwrap();
        let inputs = ExactStateStructuralFrontierInputs {
            touched_indices,
            active_depth,
            old_slot_leaves,
            new_slot_leaves,
            live_sibling_digests,
            old_combine_digests: old_evaluation.combines,
            new_combine_digests: new_evaluation.combines,
            old_root: old_evaluation.root,
            new_root: new_evaluation.root,
        };

        assert!(verify_exact_state_structural_frontier(&inputs).is_ok());
    }
}
