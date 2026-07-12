// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production coordinator for one selected-ZK recursive Block proof.
//!
//! Native block acceptance remains the cheap `BlockProof::minimal` path. This
//! module is for the asynchronous history prover: it consumes the exact
//! selected authorization proofs retained from one native-verified block,
//! chooses the canonical B8/B32/B64/B255 class, creates one fresh verified
//! ghost proof, and authors only the selected V4 recursive envelope.

use std::panic::{catch_unwind, AssertUnwindSafe};

use noid_core::TowerField;
use noid_gkr::zk_authorization::{
    verify_zk_authorization, ZkAuthCapsuleOwnerStatement, ZkAuthorizationProof,
};
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::proof::FieldShape;
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_recursive::acceptance::block_class::{
    build_selected_zk_block_proof_trace, prove_built_block, BlockClass, BlockProofEnvelope,
    BlockProofError, BLOCK_PROOF_TRANSCRIPT_DOMAIN,
};
use noid_recursive::acceptance::link::{SelectedZkBlockInput, SelectedZkBlockInputError};
use noid_recursive::acceptance::split_link::{
    begin_split_link_native_preparation, prove_built_split_link, CanonicalLadderError,
    CanonicalSplitLinkLadder, LinkProofEnvelope, LinkProofError, SplitLinkClass,
    SplitLinkPreparationError, SplitLinkTraceInput,
};
use noid_recursive::block_certificate_backend::{
    verify_accepted_block_batch_components_selected_zk, AcceptedBlockBatchComponentError,
    AcceptedBlockBatchComponentInputs, AcceptedBlockBatchComponentProof,
};
use noid_recursive::{ChainAccumulator, RecursiveConsensusState};

use crate::memory_governor::{ProofMemoryGovernor, ProofMemoryPressure};

/// One of the four canonical standalone recursive Block classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedRecursiveTier {
    B8,
    B32,
    B64,
    B255,
}

impl SelectedRecursiveTier {
    pub const fn capacity(self) -> usize {
        match self {
            Self::B8 => 8,
            Self::B32 => 32,
            Self::B64 => 64,
            Self::B255 => 255,
        }
    }

    const fn slot(self) -> usize {
        match self {
            Self::B8 => 0,
            Self::B32 => 1,
            Self::B64 => 2,
            Self::B255 => 3,
        }
    }
}

/// Borrowed freeze-locked selected class registry used by the history prover.
/// Construction rejects a misplaced tier and every legacy authorization class
/// before any recursive witness allocation begins.
pub struct SelectedRecursiveBlockClasses<'a> {
    b8: &'a BlockClass,
    b32: &'a BlockClass,
    b64: &'a BlockClass,
    b255: &'a BlockClass,
}

impl<'a> SelectedRecursiveBlockClasses<'a> {
    pub fn try_new(
        b8: &'a BlockClass,
        b32: &'a BlockClass,
        b64: &'a BlockClass,
        b255: &'a BlockClass,
    ) -> Result<Self, SelectedRecursiveProverError> {
        for (tier, class) in [(8, b8), (32, b32), (64, b64), (255, b255)] {
            class
                .validate_selected_zk_identity_for_tier(tier)
                .map_err(|source| SelectedRecursiveProverError::ClassIdentity { tier, source })?;
        }
        Ok(Self { b8, b32, b64, b255 })
    }

    fn get(&self, tier: SelectedRecursiveTier) -> &'a BlockClass {
        match tier {
            SelectedRecursiveTier::B8 => self.b8,
            SelectedRecursiveTier::B32 => self.b32,
            SelectedRecursiveTier::B64 => self.b64,
            SelectedRecursiveTier::B255 => self.b255,
        }
    }
}

/// Freeze-locked canonical Link registry used by the history coordinator.
///
/// The complete four-slot descriptor and all materialized classes are checked
/// together.  The coordinator then derives every whitelist digest internally;
/// a job cannot provide or reorder class authority.
pub struct SelectedRecursiveLinkClasses<'a> {
    classes: &'a [SplitLinkClass; CanonicalSplitLinkLadder::SLOT_COUNT],
    link_class_digests: [[u8; 32]; CanonicalSplitLinkLadder::SLOT_COUNT],
    link_post_commit_class_digests: [[u8; 32]; CanonicalSplitLinkLadder::SLOT_COUNT],
}

impl<'a> SelectedRecursiveLinkClasses<'a> {
    pub fn try_new(
        descriptor: &CanonicalSplitLinkLadder,
        classes: &'a [SplitLinkClass; CanonicalSplitLinkLadder::SLOT_COUNT],
    ) -> Result<Self, SelectedRecursiveProverError> {
        descriptor
            .validate_materialized(classes)
            .map_err(SelectedRecursiveProverError::LinkClassRegistry)?;
        for (slot, (class, expected_tier)) in classes.iter().zip([8usize, 32, 64, 255]).enumerate()
        {
            validate_link_class_binding(
                slot,
                expected_tier,
                class.slot(),
                class.ladder()[slot].tier,
            )?;
        }
        let mut link_class_digests = [[0u8; 32]; CanonicalSplitLinkLadder::SLOT_COUNT];
        let mut link_post_commit_class_digests = [[0u8; 32]; CanonicalSplitLinkLadder::SLOT_COUNT];
        for (slot, class) in classes.iter().enumerate() {
            link_class_digests[slot] = class.class_statement_digest.get().copied().ok_or(
                SelectedRecursiveProverError::LinkRegistryInvariant(
                    "materialized Link class has no statement digest",
                ),
            )?;
            link_post_commit_class_digests[slot] = *class.post_commit_class_digest();
        }
        Ok(Self {
            classes,
            link_class_digests,
            link_post_commit_class_digests,
        })
    }

    fn get(&self, tier: SelectedRecursiveTier) -> &'a SplitLinkClass {
        &self.classes[tier.slot()]
    }
}

/// Consuming inputs for exactly one native-verified accepted block.
///
/// The selected proof vector is intentionally owned and the job is neither
/// Clone nor serializable. Callers must transfer it from the bounded native
/// sidecar replay; no legacy proof or padding vector is accepted.
pub struct SelectedRecursiveBlockJob<'a> {
    pub start_consensus: &'a RecursiveConsensusState,
    pub start_accumulator: &'a ChainAccumulator,
    pub end_accumulator: &'a ChainAccumulator,
    pub component_inputs: &'a AcceptedBlockBatchComponentInputs,
    pub component_proof: &'a AcceptedBlockBatchComponentProof,
    pub selected_authorization_proofs: Vec<ZkAuthorizationProof>,
}

/// Complete standalone selected Block envelope plus its canonical class.
pub struct SelectedRecursiveBlockProof {
    pub tier: SelectedRecursiveTier,
    pub envelope: BlockProofEnvelope,
}

/// Exact predecessor of one recursive Link step.  Ordinary predecessors are
/// owned so the consuming coordinator cannot outlive or silently replace the
/// envelope after native preflight. Genesis authority is taken from the
/// selected current Link class itself.
pub enum SelectedRecursiveLinkPredecessor {
    Genesis,
    Previous {
        tier: SelectedRecursiveTier,
        envelope: LinkProofEnvelope,
    },
}

/// Consuming inputs for one Link step over a real selected Block envelope.
pub struct SelectedRecursiveLinkJob {
    pub predecessor: SelectedRecursiveLinkPredecessor,
    pub current_block: SelectedRecursiveBlockProof,
}

/// Complete recursive Link envelope and the canonical class that authored it.
pub struct SelectedRecursiveLinkProof {
    pub tier: SelectedRecursiveTier,
    pub envelope: LinkProofEnvelope,
}

/// Which transient protocol matrix a Link step requests from its local class
/// cache/rebuilder. Genesis uses the canonical matrix already owned by the
/// frozen Link registry and therefore never enters this loader boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedRecursiveMatrixKind {
    PreviousLink(SelectedRecursiveTier),
    CurrentBlock(SelectedRecursiveTier),
}

/// Immutable identity supplied by the coordinator to a sequential matrix
/// source.  It is a lookup request, not trusted authority: the phased Link API
/// rehashes the returned matrix structurally before replaying either proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedRecursiveMatrixRequest {
    kind: SelectedRecursiveMatrixKind,
    shape: FieldShape,
    statement_digest: [u8; 32],
}

impl SelectedRecursiveMatrixRequest {
    pub const fn kind(&self) -> SelectedRecursiveMatrixKind {
        self.kind
    }

    pub const fn shape(&self) -> FieldShape {
        self.shape
    }

    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
}

/// One owned transient matrix returned to the coordinator.  It exposes only a
/// borrow and is explicitly dropped before the next loader call.
pub struct LoadedSelectedRecursiveMatrix {
    matrix: FieldR1cs,
    release_probe: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl LoadedSelectedRecursiveMatrix {
    pub fn new(matrix: FieldR1cs) -> Self {
        Self {
            matrix,
            release_probe: None,
        }
    }

    fn matrix(&self) -> &FieldR1cs {
        &self.matrix
    }

    #[cfg(test)]
    fn with_release_probe(
        matrix: FieldR1cs,
        release_probe: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            matrix,
            release_probe: Some(Box::new(release_probe)),
        }
    }
}

impl Drop for LoadedSelectedRecursiveMatrix {
    fn drop(&mut self) {
        if let Some(release_probe) = self.release_probe.take() {
            release_probe();
        }
    }
}

/// On-demand local matrix provider for the production history worker.
/// Implementations should rebuild/read only the requested class and transfer
/// ownership; retaining a second matrix defeats the coordinator's RAM bound.
pub trait SelectedRecursiveMatrixSource {
    type Error: core::fmt::Display;

    fn load_matrix(
        &mut self,
        request: SelectedRecursiveMatrixRequest,
    ) -> Result<LoadedSelectedRecursiveMatrix, Self::Error>;
}

#[derive(Debug)]
pub enum SelectedRecursiveProverError {
    NonCanonicalLiveCount {
        actual: usize,
    },
    NotSingleBlock {
        actual: usize,
    },
    ComponentShape(&'static str),
    AuthorizationProofCardinality {
        expected: usize,
        actual: usize,
    },
    LegacyAuthorizationCarrier {
        proofs: usize,
        traces: usize,
    },
    AuthorizationBodyBinding {
        index: usize,
    },
    DuplicateLiveCommitment {
        first: usize,
        second: usize,
    },
    GhostProofGeneration,
    GhostProofRejected,
    LiveGhostCommitmentReuse {
        live_index: usize,
    },
    ComponentProof(AcceptedBlockBatchComponentError),
    Input(SelectedZkBlockInputError),
    ClassIdentity {
        tier: usize,
        source: BlockProofError,
    },
    LinkClassRegistry(CanonicalLadderError),
    LinkClassOrder {
        slot: usize,
        expected_tier: usize,
        actual_slot: usize,
        actual_tier: usize,
    },
    LinkRegistryInvariant(&'static str),
    MatrixLoad {
        kind: SelectedRecursiveMatrixKind,
        detail: String,
    },
    LinkPreparation(SplitLinkPreparationError),
    LinkPreparationRejected,
    MemoryPressure {
        required_mib: usize,
        available_mib: usize,
    },
    RecursiveAssemblyRejected,
    LinkAssemblyRejected,
    BlockProof(BlockProofError),
    LinkProof(LinkProofError),
}

impl core::fmt::Display for SelectedRecursiveProverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonCanonicalLiveCount { actual } => {
                write!(
                    f,
                    "{actual} live user transactions exceed the recursive ladder"
                )
            }
            Self::NotSingleBlock { actual } => {
                write!(f, "selected Block job contains {actual} accepted headers")
            }
            Self::ComponentShape(message) => write!(f, "selected component shape: {message}"),
            Self::AuthorizationProofCardinality { expected, actual } => write!(
                f,
                "selected proof count {actual} does not match live user count {expected}"
            ),
            Self::LegacyAuthorizationCarrier { proofs, traces } => write!(
                f,
                "selected job retains {proofs} legacy proofs and {traces} legacy traces"
            ),
            Self::AuthorizationBodyBinding { index } => {
                write!(f, "authorization {index} does not bind its canonical body")
            }
            Self::DuplicateLiveCommitment { first, second } => write!(
                f,
                "selected authorizations {first} and {second} reuse one source commitment"
            ),
            Self::GhostProofGeneration => write!(f, "fresh selected ghost proof failed"),
            Self::GhostProofRejected => write!(f, "fresh selected ghost proof was rejected"),
            Self::LiveGhostCommitmentReuse { live_index } => write!(
                f,
                "selected authorization {live_index} reuses the ghost source commitment"
            ),
            Self::ComponentProof(source) => {
                write!(f, "retained selected component proof rejected: {source:?}")
            }
            Self::Input(source) => write!(f, "selected recursive input rejected: {source}"),
            Self::ClassIdentity { tier, source } => {
                write!(f, "selected B{tier} class rejected: {source}")
            }
            Self::LinkClassRegistry(source) => {
                write!(f, "canonical recursive Link registry rejected: {source}")
            }
            Self::LinkClassOrder {
                slot,
                expected_tier,
                actual_slot,
                actual_tier,
            } => write!(
                f,
                "recursive Link slot {slot} must be L-B{expected_tier}, got slot {actual_slot} / B{actual_tier}"
            ),
            Self::LinkRegistryInvariant(message) => {
                write!(f, "recursive Link registry invariant: {message}")
            }
            Self::MatrixLoad { kind, detail } => {
                write!(f, "recursive {kind:?} matrix load failed: {detail}")
            }
            Self::LinkPreparation(source) => {
                write!(f, "recursive Link native preparation failed: {source}")
            }
            Self::LinkPreparationRejected => {
                write!(f, "selected recursive Link preparation panicked and was rejected")
            }
            Self::MemoryPressure {
                required_mib,
                available_mib,
            } => write!(
                f,
                "selected recursive proof needs {required_mib} MiB, {available_mib} MiB available"
            ),
            Self::RecursiveAssemblyRejected => {
                write!(f, "selected recursive assembly failed closed")
            }
            Self::LinkAssemblyRejected => {
                write!(f, "selected recursive Link assembly failed closed")
            }
            Self::BlockProof(source) => write!(f, "selected Block proof failed: {source}"),
            Self::LinkProof(source) => write!(f, "selected Link proof failed: {source}"),
        }
    }
}

impl std::error::Error for SelectedRecursiveProverError {}

impl From<ProofMemoryPressure> for SelectedRecursiveProverError {
    fn from(value: ProofMemoryPressure) -> Self {
        Self::MemoryPressure {
            required_mib: value.required_mib,
            available_mib: value.available_mib,
        }
    }
}

/// Select a canonical proof class from the exact live user-transaction count.
pub fn selected_recursive_tier(
    live_user_txs: usize,
) -> Result<SelectedRecursiveTier, SelectedRecursiveProverError> {
    match noid_chain::consensus::params::user_tx_class_tier(live_user_txs) {
        Some(8) => Ok(SelectedRecursiveTier::B8),
        Some(32) => Ok(SelectedRecursiveTier::B32),
        Some(64) => Ok(SelectedRecursiveTier::B64),
        Some(255) => Ok(SelectedRecursiveTier::B255),
        _ => Err(SelectedRecursiveProverError::NonCanonicalLiveCount {
            actual: live_user_txs,
        }),
    }
}

fn validate_link_class_binding(
    expected_slot: usize,
    expected_tier: usize,
    actual_slot: usize,
    actual_tier: usize,
) -> Result<(), SelectedRecursiveProverError> {
    if actual_slot != expected_slot || actual_tier != expected_tier {
        return Err(SelectedRecursiveProverError::LinkClassOrder {
            slot: expected_slot,
            expected_tier,
            actual_slot,
            actual_tier,
        });
    }
    Ok(())
}

#[derive(Debug)]
enum SequentialMatrixPhaseError<SourceError, PhaseError> {
    Load {
        request: SelectedRecursiveMatrixRequest,
        source: SourceError,
    },
    Phase(PhaseError),
}

/// Drive the non-genesis matrix phases with explicit ownership boundaries.
/// The previous matrix is destroyed before the source is asked for the Block
/// matrix, and the Block matrix is destroyed before matrix-free assembly can
/// begin.
fn run_sequential_matrix_phases<S, PreviousPhase, BlockPhase, Prepared, PhaseError>(
    source: &mut S,
    previous_request: SelectedRecursiveMatrixRequest,
    block_request: SelectedRecursiveMatrixRequest,
    previous_phase: PreviousPhase,
    prepare_previous: impl FnOnce(PreviousPhase, &FieldR1cs) -> Result<BlockPhase, PhaseError>,
    prepare_block: impl FnOnce(BlockPhase, &FieldR1cs) -> Result<Prepared, PhaseError>,
) -> Result<Prepared, SequentialMatrixPhaseError<S::Error, PhaseError>>
where
    S: SelectedRecursiveMatrixSource,
{
    let previous_matrix = source.load_matrix(previous_request).map_err(|source| {
        SequentialMatrixPhaseError::Load {
            request: previous_request,
            source,
        }
    })?;
    let block_phase = prepare_previous(previous_phase, previous_matrix.matrix())
        .map_err(SequentialMatrixPhaseError::Phase)?;
    drop(previous_matrix);

    let block_matrix =
        source
            .load_matrix(block_request)
            .map_err(|source| SequentialMatrixPhaseError::Load {
                request: block_request,
                source,
            })?;
    let prepared = prepare_block(block_phase, block_matrix.matrix())
        .map_err(SequentialMatrixPhaseError::Phase)?;
    drop(block_matrix);
    Ok(prepared)
}

/// Author one production selected recursive Block proof.
///
/// The process-global governor is acquired before native proof replay, ghost
/// generation, or m22+ assembly. Thus a coinbase-only block still reserves B8
/// and this background job cannot overlap the miner's native proof worker.
pub fn prove_selected_recursive_block(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob<'_>,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    prove_selected_recursive_block_with_governor(classes, job, &ProofMemoryGovernor::global(0))
}

/// Author one production Split-Link envelope around a real selected Block
/// proof, loading at most one transient child matrix at a time.
///
/// This is the honest worker boundary, not durable-queue wiring: the caller
/// must provide the previously accepted Link envelope and an on-demand local
/// matrix source.  Registry whitelists are derived from the validated
/// canonical classes and cannot be supplied by the job.
pub fn prove_selected_recursive_link<S: SelectedRecursiveMatrixSource>(
    classes: &SelectedRecursiveLinkClasses<'_>,
    job: SelectedRecursiveLinkJob,
    matrices: &mut S,
) -> Result<SelectedRecursiveLinkProof, SelectedRecursiveProverError> {
    prove_selected_recursive_link_with_governor(
        classes,
        job,
        matrices,
        &ProofMemoryGovernor::global(0),
    )
}

fn prove_selected_recursive_link_with_governor<S: SelectedRecursiveMatrixSource>(
    classes: &SelectedRecursiveLinkClasses<'_>,
    job: SelectedRecursiveLinkJob,
    matrices: &mut S,
    governor: &ProofMemoryGovernor,
) -> Result<SelectedRecursiveLinkProof, SelectedRecursiveProverError> {
    let _memory_reservation = governor.try_reserve_for_recursive_link()?;
    let SelectedRecursiveLinkJob {
        predecessor,
        current_block,
    } = job;
    let current_tier = current_block.tier;
    let class = classes.get(current_tier);
    validate_link_class_binding(
        current_tier.slot(),
        current_tier.capacity(),
        class.slot(),
        class.ladder()[class.slot()].tier,
    )?;

    let (previous_envelope, previous_slot, genesis, previous_request) = match &predecessor {
        SelectedRecursiveLinkPredecessor::Genesis => (class.genesis_envelope(), 0usize, true, None),
        SelectedRecursiveLinkPredecessor::Previous { tier, envelope } => {
            let previous_class = classes.get(*tier);
            validate_link_class_binding(
                tier.slot(),
                tier.capacity(),
                previous_class.slot(),
                previous_class.ladder()[previous_class.slot()].tier,
            )?;
            (
                envelope,
                tier.slot(),
                false,
                Some(SelectedRecursiveMatrixRequest {
                    kind: SelectedRecursiveMatrixKind::PreviousLink(*tier),
                    shape: previous_class.shape,
                    statement_digest: classes.link_class_digests[tier.slot()],
                }),
            )
        }
    };
    let block_request = SelectedRecursiveMatrixRequest {
        kind: SelectedRecursiveMatrixKind::CurrentBlock(current_tier),
        shape: class.ladder()[class.slot()].b_shape,
        statement_digest: class.ladder()[class.slot()].b_digest,
    };
    let previous_phase = begin_split_link_native_preparation(
        class,
        SplitLinkTraceInput {
            prev: previous_envelope,
            prev_slot: previous_slot,
            genesis,
            link_class_digests: classes.link_class_digests.to_vec(),
            link_post_commit_class_digests: classes.link_post_commit_class_digests.to_vec(),
            block: &current_block.envelope,
        },
    )
    .map_err(SelectedRecursiveProverError::LinkPreparation)?;

    let prepare_matrices = AssertUnwindSafe(|| {
        if let Some(previous_request) = previous_request {
            run_sequential_matrix_phases(
                matrices,
                previous_request,
                block_request,
                previous_phase,
                |phase, matrix| phase.prepare_previous_link(matrix),
                |phase, matrix| phase.prepare_current_block(matrix),
            )
            .map_err(map_sequential_link_error)
        } else {
            // The canonical genesis matrix is already owned once by the
            // frozen registry. Finish its fold before asking the source for
            // the current Block matrix; no additional genesis matrix is
            // rebuilt or cloned.
            let block_phase = previous_phase
                .prepare_previous_link(class.genesis.as_ref())
                .map_err(SelectedRecursiveProverError::LinkPreparation)?;
            let block_matrix = matrices.load_matrix(block_request).map_err(|source| {
                SelectedRecursiveProverError::MatrixLoad {
                    kind: block_request.kind,
                    detail: source.to_string(),
                }
            })?;
            let prepared = block_phase
                .prepare_current_block(block_matrix.matrix())
                .map_err(SelectedRecursiveProverError::LinkPreparation)?;
            drop(block_matrix);
            Ok(prepared)
        }
    });
    let prepared = catch_unwind(prepare_matrices)
        .map_err(|_| SelectedRecursiveProverError::LinkPreparationRejected)??;

    // Both transient child matrices are gone before the m24 Link trace and
    // proof are allocated. Internal assertion failures remain fail-closed at
    // this production boundary.
    let assemble_and_prove = AssertUnwindSafe(|| {
        let built = prepared.assemble();
        let mut challenger = FsLaneChallenger::new(b"history-link-v0");
        prove_built_split_link(class, &built, &mut challenger)
    });
    let envelope = catch_unwind(assemble_and_prove)
        .map_err(|_| SelectedRecursiveProverError::LinkAssemblyRejected)?
        .map_err(SelectedRecursiveProverError::LinkProof)?;
    Ok(SelectedRecursiveLinkProof {
        tier: current_tier,
        envelope,
    })
}

fn map_sequential_link_error<SourceError: core::fmt::Display>(
    error: SequentialMatrixPhaseError<SourceError, SplitLinkPreparationError>,
) -> SelectedRecursiveProverError {
    match error {
        SequentialMatrixPhaseError::Load { request, source } => {
            SelectedRecursiveProverError::MatrixLoad {
                kind: request.kind,
                detail: source.to_string(),
            }
        }
        SequentialMatrixPhaseError::Phase(source) => {
            SelectedRecursiveProverError::LinkPreparation(source)
        }
    }
}

fn prove_selected_recursive_block_with_governor(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob<'_>,
    governor: &ProofMemoryGovernor,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let live_count = job.component_inputs.authorization_inputs.len();
    let tier = selected_recursive_tier(live_count)?;
    validate_selected_carrier_shape(
        job.component_inputs,
        job.component_proof,
        job.selected_authorization_proofs.len(),
    )?;
    classes
        .get(tier)
        .validate_selected_zk_identity_for_tier(tier.capacity())
        .map_err(|source| SelectedRecursiveProverError::ClassIdentity {
            tier: tier.capacity(),
            source,
        })?;

    let _memory_reservation = governor.try_reserve_for_recursive_tier(tier.capacity())?;

    validate_authorization_body_bindings(
        &job.component_inputs.authorization_inputs,
        &job.component_inputs.tx_body_inputs,
        &job.component_inputs.tx_body_hashes,
    )?;
    // Do not add a third full authorization verification pass here. Native
    // accepted-batch replay already verified these exact proofs, and the
    // consuming selected builder verifies them once more against body-derived
    // aliases before exposing any recursive columns. Shape/body mismatch is
    // rejected above, and a malformed proof makes the caught assembly fail.
    verify_accepted_block_batch_components_selected_zk(
        job.start_consensus,
        job.start_accumulator,
        job.end_accumulator,
        job.component_inputs,
        job.component_proof,
    )
    .map_err(SelectedRecursiveProverError::ComponentProof)?;

    let ghost = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
        .map_err(|_| SelectedRecursiveProverError::GhostProofGeneration)?;
    let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
    let ghost_statement = ZkAuthCapsuleOwnerStatement {
        tx_body_hash: noid_gkr::ghost_tx::ghost_tx_body_hash(),
        address: ghost_body.input_owner.as_fields(),
    };
    verify_zk_authorization(ghost_statement, &ghost)
        .map_err(|_| SelectedRecursiveProverError::GhostProofRejected)?;
    reject_source_commitment_reuse(&job.selected_authorization_proofs, &ghost)?;

    let class = classes.get(tier);
    let build_and_prove = AssertUnwindSafe(|| match tier {
        SelectedRecursiveTier::B8 => build_and_prove_selected::<8>(class, job, ghost),
        SelectedRecursiveTier::B32 => build_and_prove_selected::<32>(class, job, ghost),
        SelectedRecursiveTier::B64 => build_and_prove_selected::<64>(class, job, ghost),
        SelectedRecursiveTier::B255 => build_and_prove_selected::<255>(class, job, ghost),
    });
    let envelope = catch_unwind(build_and_prove)
        .map_err(|_| SelectedRecursiveProverError::RecursiveAssemblyRejected)??;
    Ok(SelectedRecursiveBlockProof { tier, envelope })
}

fn build_and_prove_selected<const TIER: usize>(
    class: &BlockClass,
    job: SelectedRecursiveBlockJob<'_>,
    ghost: ZkAuthorizationProof,
) -> Result<BlockProofEnvelope, SelectedRecursiveProverError> {
    let input = SelectedZkBlockInput::<TIER>::try_new(
        job.start_accumulator,
        job.end_accumulator,
        job.component_inputs,
        job.component_proof,
        job.selected_authorization_proofs,
        ghost,
    )
    .map_err(SelectedRecursiveProverError::Input)?;
    let built = build_selected_zk_block_proof_trace(class, input);
    let mut challenger = FsLaneChallenger::new(BLOCK_PROOF_TRANSCRIPT_DOMAIN);
    prove_built_block(class, &built, &mut challenger)
        .map_err(SelectedRecursiveProverError::BlockProof)
}

fn validate_selected_carrier_shape(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
    selected_proof_count: usize,
) -> Result<(), SelectedRecursiveProverError> {
    validate_selected_carrier_counts(SelectedCarrierCounts {
        block_count: inputs.accepted_claim_witness.headers.len(),
        accepted_claim_count: inputs.accepted_claim_witness.accepted_block_claims.len(),
        accepted_claim_hash_count: inputs.accepted_claim_hash_inputs.len(),
        legacy_proof_count: inputs.authorization_witnesses.len(),
        legacy_trace_count: inputs.authorization_traces.len(),
        authorization_count: inputs.authorization_inputs.len(),
        selected_proof_count,
        authorization_total: inputs.authorization_totals.user_tx_count,
        tx_body_count: inputs.tx_body_inputs.len(),
        tx_body_hash_count: inputs.tx_body_hashes.len(),
        legacy_exact_state_count: inputs.exact_state_killshot_inputs.len(),
        structural_exact_state_count: inputs.exact_state_structural_inputs.len(),
        exact_state_proof_count: proof.exact_state.len(),
    })
}

#[derive(Clone, Copy)]
struct SelectedCarrierCounts {
    block_count: usize,
    accepted_claim_count: usize,
    accepted_claim_hash_count: usize,
    legacy_proof_count: usize,
    legacy_trace_count: usize,
    authorization_count: usize,
    selected_proof_count: usize,
    authorization_total: usize,
    tx_body_count: usize,
    tx_body_hash_count: usize,
    legacy_exact_state_count: usize,
    structural_exact_state_count: usize,
    exact_state_proof_count: usize,
}

fn validate_selected_carrier_counts(
    counts: SelectedCarrierCounts,
) -> Result<(), SelectedRecursiveProverError> {
    if counts.block_count != 1 {
        return Err(SelectedRecursiveProverError::NotSingleBlock {
            actual: counts.block_count,
        });
    }
    if counts.accepted_claim_count != 1
        || counts.accepted_claim_hash_count != 1
        || counts.legacy_exact_state_count != 1
        || counts.structural_exact_state_count != 1
        || counts.exact_state_proof_count != 1
    {
        return Err(SelectedRecursiveProverError::ComponentShape(
            "one block requires one claim and one exact-state component",
        ));
    }
    if counts.legacy_proof_count != 0 || counts.legacy_trace_count != 0 {
        return Err(SelectedRecursiveProverError::LegacyAuthorizationCarrier {
            proofs: counts.legacy_proof_count,
            traces: counts.legacy_trace_count,
        });
    }
    if counts.selected_proof_count != counts.authorization_count {
        return Err(
            SelectedRecursiveProverError::AuthorizationProofCardinality {
                expected: counts.authorization_count,
                actual: counts.selected_proof_count,
            },
        );
    }
    if counts.authorization_total != counts.authorization_count {
        return Err(SelectedRecursiveProverError::ComponentShape(
            "authorization total differs from the canonical live prefix",
        ));
    }
    if counts.tx_body_count != counts.authorization_count + 1
        || counts.tx_body_hash_count != counts.tx_body_count
    {
        return Err(SelectedRecursiveProverError::ComponentShape(
            "body spine count differs from coinbase plus live users",
        ));
    }
    Ok(())
}

fn validate_authorization_body_bindings(
    authorization_inputs: &[noid_recursive::block_certificate_backend::AuthorizationComponentInput],
    tx_body_inputs: &[noid_gkr::SpineInputs],
    tx_body_hashes: &[[noid_core::Block128; 2]],
) -> Result<(), SelectedRecursiveProverError> {
    use noid_tx::body_hash::{TX8X2_LEAF_FLAGS, TX8X2_LEAF_INPUT_OWNER};

    let circuit = noid_gkr::SpineCircuit::build();
    for (index, authorization) in authorization_inputs.iter().enumerate() {
        let body_index = index + 1;
        let body = &tx_body_inputs[body_index];
        let body_hash = noid_gkr::compute_tx_body_hash(&circuit, body);
        let flags = body.leaves[TX8X2_LEAF_FLAGS];
        let validity_bitmap = u16::try_from(flags[0].0).ok();
        let live_input_count = validity_bitmap
            .map(|bitmap| (bitmap & ((1u16 << noid_tx::TX_INPUTS) - 1)).count_ones() as u8);
        if authorization.block_index != 0
            || authorization.tx_index != body_index
            || authorization.tx_body_hash != body_hash
            || authorization.public.tx_body_hash != body_hash
            || tx_body_hashes[body_index] != body_hash
            || authorization.public.expected_address != body.leaves[TX8X2_LEAF_INPUT_OWNER]
            || flags[1] != noid_core::Block128::ZERO
            || live_input_count != Some(authorization.live_input_count)
        {
            return Err(SelectedRecursiveProverError::AuthorizationBodyBinding { index });
        }
    }
    Ok(())
}

fn reject_source_commitment_reuse(
    live: &[ZkAuthorizationProof],
    ghost: &ZkAuthorizationProof,
) -> Result<(), SelectedRecursiveProverError> {
    for second in 0..live.len() {
        for first in 0..second {
            if live[first].source_commitment.cap.hashes == live[second].source_commitment.cap.hashes
            {
                return Err(SelectedRecursiveProverError::DuplicateLiveCommitment {
                    first,
                    second,
                });
            }
        }
        if live[second].source_commitment.cap.hashes == ghost.source_commitment.cap.hashes {
            return Err(SelectedRecursiveProverError::LiveGhostCommitmentReuse {
                live_index: second,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::Block128;
    use noid_gkr::owner_auth::{OwnerAuthLayout, OwnerAuthPublicInputs};
    use noid_ivc_core::field::F128;
    use noid_ivc_core::field_circuit::FieldR1csBuilder;
    use noid_poseidon2b::primitives::Address;
    use noid_recursive::block_certificate_backend::AuthorizationComponentInput;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn dispatches_all_four_canonical_tiers() {
        for (live, expected) in [
            (0, SelectedRecursiveTier::B8),
            (9, SelectedRecursiveTier::B32),
            (33, SelectedRecursiveTier::B64),
            (65, SelectedRecursiveTier::B255),
        ] {
            assert_eq!(selected_recursive_tier(live).unwrap(), expected);
        }
        assert!(matches!(
            selected_recursive_tier(256),
            Err(SelectedRecursiveProverError::NonCanonicalLiveCount { actual: 256 })
        ));
    }

    fn user_body() -> TxBody {
        let owner = Address([0x42; 32]);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 11,
            creation_id: 3,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 9,
            amount: 10,
            owner,
        };
        TxBody {
            epoch_anchor: [3u8; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    #[test]
    fn body_binding_rejects_statement_mismatch_before_recursive_build() {
        let body = user_body();
        let user_spine = noid_gkr::spine_inputs_from_body(&body);
        let circuit = noid_gkr::SpineCircuit::build();
        let hash = noid_gkr::compute_tx_body_hash(&circuit, &user_spine);
        let authorization = AuthorizationComponentInput {
            block_index: 0,
            tx_index: 1,
            tx_body_hash: hash,
            live_input_count: 1,
            public: OwnerAuthPublicInputs {
                layout: OwnerAuthLayout::FIXED,
                tx_body_hash: hash,
                expected_address: body.input_owner.as_fields(),
            },
        };
        let bodies = vec![user_spine.clone(), user_spine];
        let hashes = vec![hash, hash];
        let mut authorizations = vec![authorization];
        validate_authorization_body_bindings(&authorizations, &bodies, &hashes).unwrap();

        authorizations[0].public.expected_address[0] += Block128::ONE;
        assert!(matches!(
            validate_authorization_body_bindings(&authorizations, &bodies, &hashes),
            Err(SelectedRecursiveProverError::AuthorizationBodyBinding { index: 0 })
        ));
    }

    #[test]
    fn carrier_shape_rejects_count_mismatch_and_legacy_vectors() {
        let canonical = SelectedCarrierCounts {
            block_count: 1,
            accepted_claim_count: 1,
            accepted_claim_hash_count: 1,
            legacy_proof_count: 0,
            legacy_trace_count: 0,
            authorization_count: 0,
            selected_proof_count: 1,
            authorization_total: 0,
            tx_body_count: 1,
            tx_body_hash_count: 1,
            legacy_exact_state_count: 1,
            structural_exact_state_count: 1,
            exact_state_proof_count: 1,
        };
        assert!(matches!(
            validate_selected_carrier_counts(canonical),
            Err(
                SelectedRecursiveProverError::AuthorizationProofCardinality {
                    expected: 0,
                    actual: 1
                }
            )
        ));

        let legacy = SelectedCarrierCounts {
            selected_proof_count: 0,
            legacy_proof_count: 1,
            ..canonical
        };
        assert!(matches!(
            validate_selected_carrier_counts(legacy),
            Err(SelectedRecursiveProverError::LegacyAuthorizationCarrier {
                proofs: 1,
                traces: 0
            })
        ));
    }

    fn tiny_matrix(tag: u64) -> FieldR1cs {
        let mut builder = FieldR1csBuilder::new();
        builder.alloc_public_f128(F128::new(tag, 0));
        builder.build().0
    }

    struct OrderedMatrixSource {
        previous: Option<FieldR1cs>,
        block: Option<FieldR1cs>,
        resident: Arc<AtomicBool>,
        calls: Vec<SelectedRecursiveMatrixKind>,
    }

    impl SelectedRecursiveMatrixSource for OrderedMatrixSource {
        type Error = &'static str;

        fn load_matrix(
            &mut self,
            request: SelectedRecursiveMatrixRequest,
        ) -> Result<LoadedSelectedRecursiveMatrix, Self::Error> {
            if self.resident.swap(true, Ordering::AcqRel) {
                return Err("second matrix loaded before first matrix release");
            }
            self.calls.push(request.kind());
            let matrix = match request.kind() {
                SelectedRecursiveMatrixKind::PreviousLink(_) => self.previous.take(),
                SelectedRecursiveMatrixKind::CurrentBlock(_) => self.block.take(),
            }
            .ok_or("requested matrix is unavailable")?;
            let resident = Arc::clone(&self.resident);
            Ok(LoadedSelectedRecursiveMatrix::with_release_probe(
                matrix,
                move || resident.store(false, Ordering::Release),
            ))
        }
    }

    fn request(
        kind: SelectedRecursiveMatrixKind,
        matrix: &FieldR1cs,
    ) -> SelectedRecursiveMatrixRequest {
        SelectedRecursiveMatrixRequest {
            kind,
            shape: FieldShape::of(matrix),
            statement_digest: matrix.structural_statement_digest(),
        }
    }

    #[test]
    fn sequential_link_driver_releases_previous_before_loading_block() {
        let previous = tiny_matrix(11);
        let block = tiny_matrix(22);
        let previous_request = request(
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8),
            &previous,
        );
        let block_request = request(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B32),
            &block,
        );
        let resident = Arc::new(AtomicBool::new(false));
        let mut source = OrderedMatrixSource {
            previous: Some(previous),
            block: Some(block),
            resident: Arc::clone(&resident),
            calls: Vec::new(),
        };

        let output = run_sequential_matrix_phases(
            &mut source,
            previous_request,
            block_request,
            (),
            |(), matrix| {
                (FieldShape::of(matrix) == previous_request.shape()
                    && matrix.structural_statement_digest() == previous_request.statement_digest())
                .then_some(7usize)
                .ok_or("previous matrix identity")
            },
            |phase, matrix| {
                (phase == 7
                    && FieldShape::of(matrix) == block_request.shape()
                    && matrix.structural_statement_digest() == block_request.statement_digest())
                .then_some(phase + 1)
                .ok_or("block matrix identity")
            },
        )
        .expect("honest sequential matrix phases");

        assert_eq!(output, 8);
        assert_eq!(
            source.calls,
            vec![previous_request.kind(), block_request.kind()]
        );
        assert!(!resident.load(Ordering::Acquire));
    }

    #[test]
    fn sequential_link_driver_rejects_substitution_before_block_load() {
        let expected_previous = tiny_matrix(31);
        let substituted_previous = tiny_matrix(32);
        let block = tiny_matrix(41);
        let previous_request = request(
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B64),
            &expected_previous,
        );
        let block_request = request(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B255),
            &block,
        );
        let resident = Arc::new(AtomicBool::new(false));
        let mut source = OrderedMatrixSource {
            previous: Some(substituted_previous),
            block: Some(block),
            resident: Arc::clone(&resident),
            calls: Vec::new(),
        };

        let error = run_sequential_matrix_phases(
            &mut source,
            previous_request,
            block_request,
            (),
            |(), matrix| {
                (matrix.structural_statement_digest() == previous_request.statement_digest())
                    .then_some(())
                    .ok_or("previous matrix identity")
            },
            |(), _matrix| Ok::<_, &'static str>(()),
        )
        .expect_err("same-shape matrix substitution must fail");
        assert!(matches!(
            error,
            SequentialMatrixPhaseError::Phase("previous matrix identity")
        ));
        assert_eq!(source.calls, vec![previous_request.kind()]);
        assert!(!resident.load(Ordering::Acquire));
        assert!(source.block.is_some(), "Block matrix was never loaded");
    }

    #[test]
    fn link_class_binding_rejects_slot_and_tier_tamper() {
        validate_link_class_binding(2, 64, 2, 64).expect("canonical L-B64 binding");
        assert!(matches!(
            validate_link_class_binding(2, 64, 1, 64),
            Err(SelectedRecursiveProverError::LinkClassOrder {
                slot: 2,
                expected_tier: 64,
                actual_slot: 1,
                actual_tier: 64,
            })
        ));
        assert!(matches!(
            validate_link_class_binding(2, 64, 2, 32),
            Err(SelectedRecursiveProverError::LinkClassOrder {
                slot: 2,
                expected_tier: 64,
                actual_slot: 2,
                actual_tier: 32,
            })
        ));
    }

    #[test]
    fn production_link_coordinator_uses_only_consuming_phased_api() {
        let source = include_str!("recursive_prover.rs");
        let coordinator = source
            .split("fn prove_selected_recursive_link_with_governor")
            .nth(1)
            .expect("production Link coordinator")
            .split("fn map_sequential_link_error")
            .next()
            .expect("coordinator boundary");
        assert!(coordinator.contains("try_reserve_for_recursive_link"));
        assert!(coordinator.contains("begin_split_link_native_preparation"));
        assert!(coordinator.contains("run_sequential_matrix_phases"));
        assert!(coordinator.contains(".prepare_previous_link(class.genesis.as_ref())"));
        assert!(coordinator.contains(".prepare_current_block(block_matrix.matrix())"));
        assert!(coordinator.contains("drop(block_matrix)"));
        assert!(coordinator.contains("prepared.assemble()"));
        assert!(coordinator.contains("prove_built_split_link"));
        assert!(!coordinator.contains("build_split_link("));
        assert!(!coordinator.contains("SplitLinkInput"));
    }
}
