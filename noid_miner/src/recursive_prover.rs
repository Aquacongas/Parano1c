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

use crate::memory_governor::{ProofMemoryGovernor, ProofMemoryPressure, ProofMemoryReservation};
use noid_block::SelectedRecursiveBlockArtifacts;
use noid_gkr::zk_authorization::ZkAuthorizationProof;
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

/// Consuming authority for exactly one natively accepted and component-
/// verified block.
///
/// The field is private and the job is neither Clone nor serializable.  The
/// only constructor requires the opaque seal minted by `noid_block` after its
/// sole native component verification; arbitrary DTOs, proofs, accumulator
/// substitutions, legacy proofs, and padding vectors cannot enter this API.
pub struct SelectedRecursiveBlockJob {
    artifacts: SelectedRecursiveBlockArtifacts,
}

impl SelectedRecursiveBlockJob {
    pub fn from_native_verified(artifacts: SelectedRecursiveBlockArtifacts) -> Self {
        Self { artifacts }
    }
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

/// One process-global m24 admission spanning a selected Block+Link sequence.
///
/// Production callers must begin the session before reconstructing the
/// `noid_block` accepted-batch artifacts used to construct
/// [`SelectedRecursiveBlockJob`].  The single reservation then remains live
/// through both proof phases, preventing native mining and standalone history
/// workers from overlapping either reconstruction or proving.  The type is
/// intentionally not `Clone`; its `&mut self` methods serialize use of the one
/// reservation. Dropping it releases admission during normal return, unwind,
/// or cancellation.
#[must_use = "dropping the session releases the selected-history memory reservation"]
pub struct SelectedHistoryProofSession {
    _reservation: ProofMemoryReservation,
}

impl SelectedHistoryProofSession {
    /// Prove the selected Block while reusing this session's already-held m24
    /// reservation. No second governor admission is attempted.
    pub fn prove_block(
        &mut self,
        classes: &SelectedRecursiveBlockClasses<'_>,
        job: SelectedRecursiveBlockJob,
    ) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
        prove_selected_recursive_block_in_reserved_session(classes, job)
    }

    /// Prove the following Link while retaining the same reservation acquired
    /// before Block artifact reconstruction.
    pub fn prove_link<S: SelectedRecursiveMatrixSource>(
        &mut self,
        classes: &SelectedRecursiveLinkClasses<'_>,
        job: SelectedRecursiveLinkJob,
        matrices: &mut S,
    ) -> Result<SelectedRecursiveLinkProof, SelectedRecursiveProverError> {
        prove_selected_recursive_link_in_reserved_session(classes, job, matrices)
    }
}

/// Acquire the full m24/8 GiB selected-history envelope from the process-wide
/// proof governor. Call this before reconstructing any accepted-block proof
/// artifacts that will feed [`SelectedHistoryProofSession::prove_block`].
pub fn begin_selected_history_proof_session(
) -> Result<SelectedHistoryProofSession, SelectedRecursiveProverError> {
    begin_selected_history_proof_session_with_governor(&ProofMemoryGovernor::global(0))
}

fn begin_selected_history_proof_session_with_governor(
    governor: &ProofMemoryGovernor,
) -> Result<SelectedHistoryProofSession, SelectedRecursiveProverError> {
    Ok(SelectedHistoryProofSession {
        _reservation: governor.try_reserve_for_selected_history_session()?,
    })
}

#[cfg(test)]
fn begin_selected_history_proof_session_with_available(
    governor: &ProofMemoryGovernor,
    available_mib: Option<usize>,
) -> Result<SelectedHistoryProofSession, SelectedRecursiveProverError> {
    Ok(SelectedHistoryProofSession {
        _reservation: governor.try_reserve_selected_history_with_available(available_mib)?,
    })
}

/// Which transient protocol matrix a Link step requests from its local class
/// cache/rebuilder.  Every child matrix, including canonical genesis T, enters
/// through this boundary so the frozen registry never pins an m24 `FieldR1cs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedRecursiveMatrixKind {
    GenesisLink,
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
    matrix: Option<FieldR1cs>,
    release_callback: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl LoadedSelectedRecursiveMatrix {
    pub fn new(matrix: FieldR1cs) -> Self {
        Self {
            matrix: Some(matrix),
            release_callback: None,
        }
    }

    /// Borrow the transient matrix without separating it from its release
    /// callback. Callers must retain this RAII wrapper for the entire borrow;
    /// dropping it releases the source's one-matrix admission.
    pub fn matrix(&self) -> &FieldR1cs {
        self.matrix
            .as_ref()
            .expect("loaded recursive matrix exists until wrapper drop")
    }

    pub(crate) fn with_release_callback(
        matrix: FieldR1cs,
        release_callback: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            matrix: Some(matrix),
            release_callback: Some(Box::new(release_callback)),
        }
    }
}

impl Drop for LoadedSelectedRecursiveMatrix {
    fn drop(&mut self) {
        // Release admission only after the multi-GiB matrix vectors have been
        // destroyed. Firing the callback first would let another thread begin
        // decoding while the old allocation is still being freed.
        drop(self.matrix.take());
        if let Some(release_callback) = self.release_callback.take() {
            release_callback();
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
    GhostProofGeneration,
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
            Self::GhostProofGeneration => write!(f, "fresh selected ghost proof failed"),
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
                write!(
                    f,
                    "selected recursive Link preparation panicked and was rejected"
                )
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
    job: SelectedRecursiveBlockJob,
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
    prove_selected_recursive_link_in_reserved_session(classes, job, matrices)
}

/// Cryptographic Link body entered only after a standalone or session-level
/// reservation has been acquired. Keep governor admission out of this path so
/// a Block+Link session never self-conflicts on the single-proof ledger.
fn prove_selected_recursive_link_in_reserved_session<S: SelectedRecursiveMatrixSource>(
    classes: &SelectedRecursiveLinkClasses<'_>,
    job: SelectedRecursiveLinkJob,
    matrices: &mut S,
) -> Result<SelectedRecursiveLinkProof, SelectedRecursiveProverError> {
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
        SelectedRecursiveLinkPredecessor::Genesis => (
            class.genesis_envelope(),
            0usize,
            true,
            SelectedRecursiveMatrixRequest {
                kind: SelectedRecursiveMatrixKind::GenesisLink,
                shape: class.shape,
                statement_digest: class.genesis_digest,
            },
        ),
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
                SelectedRecursiveMatrixRequest {
                    kind: SelectedRecursiveMatrixKind::PreviousLink(*tier),
                    shape: previous_class.shape,
                    statement_digest: classes.link_class_digests[tier.slot()],
                },
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
        run_sequential_matrix_phases(
            matrices,
            previous_request,
            block_request,
            previous_phase,
            |phase, matrix| phase.prepare_previous_link(matrix),
            |phase, matrix| phase.prepare_current_block(matrix),
        )
        .map_err(map_sequential_link_error)
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
    job: SelectedRecursiveBlockJob,
    governor: &ProofMemoryGovernor,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let tier = preflight_selected_recursive_block(classes, &job)?;
    let _memory_reservation = governor.try_reserve_for_recursive_tier(tier.capacity())?;
    prove_selected_recursive_block_after_admission(classes, job, tier)
}

/// Selected Block entry for an already-admitted history session.  The caller
/// owns the full m24 reservation before artifact reconstruction, so this path
/// must never attempt a tier-local reservation.
fn prove_selected_recursive_block_in_reserved_session(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let tier = preflight_selected_recursive_block(classes, &job)?;
    prove_selected_recursive_block_after_admission(classes, job, tier)
}

fn preflight_selected_recursive_block(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: &SelectedRecursiveBlockJob,
) -> Result<SelectedRecursiveTier, SelectedRecursiveProverError> {
    let live_count = job.artifacts.live_authorization_count();
    let tier = selected_recursive_tier(live_count)?;
    classes
        .get(tier)
        .validate_selected_zk_identity_for_tier(tier.capacity())
        .map_err(|source| SelectedRecursiveProverError::ClassIdentity {
            tier: tier.capacity(),
            source,
        })?;
    Ok(tier)
}

/// The byte-for-byte cryptographic Block path shared by standalone and
/// session-level admission.
fn prove_selected_recursive_block_after_admission(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob,
    tier: SelectedRecursiveTier,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let ghost = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
        .map_err(|_| SelectedRecursiveProverError::GhostProofGeneration)?;

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
    job: SelectedRecursiveBlockJob,
    ghost: ZkAuthorizationProof,
) -> Result<BlockProofEnvelope, SelectedRecursiveProverError> {
    let (
        start_accumulator,
        end_accumulator,
        component_inputs,
        component_proof,
        selected_authorization_proofs,
    ) = job.artifacts.into_recursive_builder_parts();
    let input = SelectedZkBlockInput::<TIER>::try_new(
        &start_accumulator,
        &end_accumulator,
        &component_inputs,
        &component_proof,
        selected_authorization_proofs,
        ghost,
    )
    .map_err(SelectedRecursiveProverError::Input)?;
    let built = build_selected_zk_block_proof_trace(class, input);
    let mut challenger = FsLaneChallenger::new(BLOCK_PROOF_TRANSCRIPT_DOMAIN);
    prove_built_block(class, &built, &mut challenger)
        .map_err(SelectedRecursiveProverError::BlockProof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::field::F128;
    use noid_ivc_core::field_circuit::FieldR1csBuilder;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[test]
    fn selected_history_session_maps_pressure_excludes_overlap_and_reopens() {
        let undersized = ProofMemoryGovernor::new(4 * 1024);
        assert!(matches!(
            begin_selected_history_proof_session_with_available(&undersized, None),
            Err(SelectedRecursiveProverError::MemoryPressure {
                required_mib: 8192,
                available_mib: 4096,
            })
        ));

        let governor = ProofMemoryGovernor::new(8 * 1024);
        let session = begin_selected_history_proof_session_with_available(&governor, None)
            .expect("full m24 session admission");
        assert!(matches!(
            governor.try_reserve_for_user_txs(1),
            Err(ProofMemoryPressure {
                required_mib: 2048,
                available_mib: 0,
            })
        ));
        assert!(matches!(
            governor.try_reserve_for_recursive_tier(8),
            Err(ProofMemoryPressure {
                required_mib: 2048,
                available_mib: 0,
            })
        ));
        assert!(matches!(
            governor.try_reserve_for_recursive_link(),
            Err(ProofMemoryPressure {
                required_mib: 8192,
                available_mib: 0,
            })
        ));

        drop(session);
        assert!(begin_selected_history_proof_session_with_available(&governor, None).is_ok());

        let unwind_governor = governor.clone();
        let unwound = std::panic::catch_unwind(move || {
            let _session =
                begin_selected_history_proof_session_with_available(&unwind_governor, None)
                    .expect("session admission before synthetic panic");
            panic!("synthetic selected-history session panic");
        });
        assert!(unwound.is_err());
        assert!(begin_selected_history_proof_session_with_available(&governor, None).is_ok());
    }

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

    #[test]
    fn selected_block_consumes_native_verified_seal_without_reverification() {
        let source = include_str!("recursive_prover.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("use noid_block::SelectedRecursiveBlockArtifacts;"));
        assert!(!production.contains("verify_accepted_block_batch_components"));
        assert!(!production.contains("compute_tx_body_hash"));
        assert!(!production.contains("verify_zk_authorization"));

        let job = production
            .split("pub struct SelectedRecursiveBlockJob")
            .nth(1)
            .expect("selected job declaration")
            .split("impl SelectedRecursiveBlockJob")
            .next()
            .expect("selected job boundary");
        assert!(job.contains("artifacts: SelectedRecursiveBlockArtifacts"));
        assert!(!job.contains("pub artifacts:"));

        let builder = production
            .split("fn build_and_prove_selected<const TIER: usize>")
            .nth(1)
            .expect("selected builder")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert_eq!(
            builder.matches("into_recursive_builder_parts()").count(),
            1,
            "the sealed B255 carrier is consumed exactly once"
        );
        assert!(builder.contains("SelectedZkBlockInput::<TIER>::try_new("));
        assert!(builder.contains("build_selected_zk_block_proof_trace(class, input)"));
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
                SelectedRecursiveMatrixKind::GenesisLink
                | SelectedRecursiveMatrixKind::PreviousLink(_) => self.previous.take(),
                SelectedRecursiveMatrixKind::CurrentBlock(_) => self.block.take(),
            }
            .ok_or("requested matrix is unavailable")?;
            let resident = Arc::clone(&self.resident);
            Ok(LoadedSelectedRecursiveMatrix::with_release_callback(
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
    fn sequential_link_driver_releases_genesis_before_loading_block() {
        let genesis = tiny_matrix(23);
        let block = tiny_matrix(24);
        let genesis_request = request(SelectedRecursiveMatrixKind::GenesisLink, &genesis);
        let block_request = request(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
            &block,
        );
        let resident = Arc::new(AtomicBool::new(false));
        let mut source = OrderedMatrixSource {
            previous: Some(genesis),
            block: Some(block),
            resident: Arc::clone(&resident),
            calls: Vec::new(),
        };

        run_sequential_matrix_phases(
            &mut source,
            genesis_request,
            block_request,
            (),
            |(), matrix| {
                (matrix.structural_statement_digest() == genesis_request.statement_digest())
                    .then_some(())
                    .ok_or("genesis matrix identity")
            },
            |(), matrix| {
                (matrix.structural_statement_digest() == block_request.statement_digest())
                    .then_some(())
                    .ok_or("block matrix identity")
            },
        )
        .expect("honest genesis-to-block phases");

        assert_eq!(
            source.calls,
            vec![
                SelectedRecursiveMatrixKind::GenesisLink,
                block_request.kind()
            ]
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
        let standalone = source
            .split("fn prove_selected_recursive_link_with_governor")
            .nth(1)
            .expect("standalone Link admission")
            .split("fn prove_selected_recursive_link_in_reserved_session")
            .next()
            .expect("standalone admission boundary");
        assert!(standalone.contains("try_reserve_for_recursive_link"));
        assert!(standalone.contains("prove_selected_recursive_link_in_reserved_session"));

        let coordinator = source
            .split("fn prove_selected_recursive_link_in_reserved_session")
            .nth(1)
            .expect("reserved production Link coordinator")
            .split("fn map_sequential_link_error")
            .next()
            .expect("coordinator boundary");
        assert!(!coordinator.contains("try_reserve"));
        assert!(coordinator.contains("begin_split_link_native_preparation"));
        assert!(coordinator.contains("run_sequential_matrix_phases"));
        assert!(coordinator.contains("SelectedRecursiveMatrixKind::GenesisLink"));
        assert!(!coordinator.contains("class.genesis.as_ref()"));
        assert!(coordinator.contains(".prepare_current_block(matrix)"));
        assert!(coordinator.contains("prepared.assemble()"));
        assert!(coordinator.contains("prove_built_split_link"));
        assert!(!coordinator.contains("build_split_link("));
        assert!(!coordinator.contains("SplitLinkInput"));
    }

    #[test]
    fn reserved_session_paths_never_reenter_memory_governor() {
        let source = include_str!("recursive_prover.rs");
        let session_impl = source
            .split("impl SelectedHistoryProofSession")
            .nth(1)
            .expect("selected-history session impl")
            .split("pub fn begin_selected_history_proof_session")
            .next()
            .expect("session impl boundary");
        assert!(session_impl.contains("&mut self"));
        assert!(session_impl.contains("prove_selected_recursive_block_in_reserved_session"));
        assert!(session_impl.contains("prove_selected_recursive_link_in_reserved_session"));
        assert!(!session_impl.contains("try_reserve"));

        let block_reserved = source
            .split("fn prove_selected_recursive_block_in_reserved_session")
            .nth(1)
            .expect("reserved Block path")
            .split("fn preflight_selected_recursive_block")
            .next()
            .expect("reserved Block boundary");
        assert!(!block_reserved.contains("try_reserve"));

        let block_body = source
            .split("fn preflight_selected_recursive_block")
            .nth(1)
            .expect("reserved Block preflight/body")
            .split("fn build_and_prove_selected")
            .next()
            .expect("reserved Block body boundary");
        assert!(!block_body.contains("try_reserve"));

        let link_reserved = source
            .split("fn prove_selected_recursive_link_in_reserved_session")
            .nth(1)
            .expect("reserved Link path")
            .split("fn map_sequential_link_error")
            .next()
            .expect("reserved Link boundary");
        assert!(!link_reserved.contains("try_reserve"));

        let declaration = source
            .split("pub struct SelectedHistoryProofSession")
            .next()
            .expect("session declaration prefix")
            .rsplit_once('\n')
            .map(|(prefix, _)| prefix)
            .unwrap_or_default();
        let declaration_tail = &declaration[declaration.len().saturating_sub(160)..];
        assert!(!declaration_tail.contains("derive(Clone"));
    }
}
