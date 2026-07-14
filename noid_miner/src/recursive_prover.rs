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
use std::sync::{
    atomic::{AtomicU8, Ordering as AtomicOrdering},
    Arc, Once,
};
use std::time::Instant;

use crate::topology_gate::{
    ProofTopologyAdmissionError, ProofTopologyGate, ProofTopologyReservation,
};
use crate::{install_selected_history_cpu, ProcessCpuBudgetError, SelectedHistoryCpuStage};
use noid_block::SelectedRecursiveBlockArtifacts;
use noid_gkr::zk_authorization::ZkAuthorizationProof;
use noid_ivc_core::field_r1cs::{CompactFieldR1cs, FieldR1cs};
use noid_ivc_core::proof::FieldShape;
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_recursive::acceptance::block_class::{
    build_selected_zk_block_proof_trace, build_selected_zk_block_proof_trace_established,
    build_selected_zk_block_proof_witness_established, prove_built_block,
    prove_built_block_compact, prove_built_block_compact_locally_authored,
    prove_built_block_locally_authored, BlockClass, BlockProofEnvelope, BlockProofError,
    LocallyAuthoredBlockReplay, BLOCK_PROOF_TRANSCRIPT_DOMAIN,
};
use noid_recursive::acceptance::link::{SelectedZkBlockInput, SelectedZkBlockInputError};
use noid_recursive::acceptance::split_link::{
    begin_split_link_native_preparation, prove_built_split_link, prove_built_split_link_compact,
    prove_built_split_link_compact_locally_authored, prove_built_split_link_locally_authored,
    CanonicalLadderError, CanonicalSplitLinkLadder, LinkProofEnvelope, LinkProofError,
    LocallyAuthoredLinkReplay, SplitLinkClass, SplitLinkPreparationError, SplitLinkTraceInput,
};

/// Developer-only escape hatch for parity diagnostics. Official optimized
/// binaries always use the established authenticated matrix path even if a
/// stale service environment still contains the historical override.
fn force_matrix_rehash_for_diagnostics() -> bool {
    let requested = std::env::var_os("NOID_ALWAYS_REHASH_MATRICES").is_some();
    if matrix_rehash_override_enabled(requested, cfg!(any(test, debug_assertions))) {
        return true;
    }
    if requested {
        static WARN_RELEASE_OVERRIDE_IGNORED: Once = Once::new();
        WARN_RELEASE_OVERRIDE_IGNORED.call_once(|| {
            tracing::warn!(
                "NOID_ALWAYS_REHASH_MATRICES is ignored by optimized production binaries"
            );
        });
    }
    false
}

const fn matrix_rehash_override_enabled(requested: bool, diagnostic_build: bool) -> bool {
    requested && diagnostic_build
}

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

    /// Reborrow classes already authenticated and fully validated by the
    /// pinned registry decoder. This constructor is crate-private so an
    /// external caller cannot turn unchecked classes into prover authority.
    pub(crate) fn from_pinned_materialization(
        b8: &'a BlockClass,
        b32: &'a BlockClass,
        b64: &'a BlockClass,
        b255: &'a BlockClass,
    ) -> Self {
        Self { b8, b32, b64, b255 }
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
        Self::from_pinned_materialization(classes)
    }

    /// Reborrow a materialization minted by the pinned full-registry decoder
    /// without replaying the descriptor's expensive fixed-table validation
    /// on every worker drain.
    pub(crate) fn from_pinned_materialization(
        classes: &'a [SplitLinkClass; CanonicalSplitLinkLadder::SLOT_COUNT],
    ) -> Result<Self, SelectedRecursiveProverError> {
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

    /// Every canonical matrix artifact identity a node must hold locally, in
    /// preflight order: genesis T, the four Link tiers, the four Block tiers.
    /// All shapes and digests come from the validated frozen registry — a
    /// pack file can therefore be trust-installed only against these pins.
    pub fn canonical_artifact_identities(
        &self,
    ) -> [crate::SelectedRecursiveMatrixArtifactIdentity; 9] {
        use crate::SelectedRecursiveMatrixArtifactIdentity as Identity;
        let tiers = [
            SelectedRecursiveTier::B8,
            SelectedRecursiveTier::B32,
            SelectedRecursiveTier::B64,
            SelectedRecursiveTier::B255,
        ];
        let genesis_class = &self.classes[0];
        let mut identities = [Identity::new(
            SelectedRecursiveMatrixKind::GenesisLink,
            genesis_class.shape,
            genesis_class.genesis_digest,
        ); 9];
        for (index, tier) in tiers.into_iter().enumerate() {
            let class = self.get(tier);
            identities[1 + index] = Identity::new(
                SelectedRecursiveMatrixKind::PreviousLink(tier),
                class.shape,
                self.link_class_digests[tier.slot()],
            );
            let info = &class.ladder()[class.slot()];
            identities[5 + index] = Identity::new(
                SelectedRecursiveMatrixKind::CurrentBlock(tier),
                info.b_shape,
                info.b_digest,
            );
        }
        identities
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
    /// Present only on the pipelined authoring path. The private one-shot
    /// capability cannot be reconstructed from a durable/network envelope.
    locally_authored_replay: Option<LocallyAuthoredBlockReplay>,
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
    /// Private-process authority paired with an envelope decoded from the
    /// immediately preceding in-memory terminal package. Only
    /// [`SelectedRecursiveLocalLinkReplay::bind_decoded_predecessor`] can
    /// construct this path.
    PreviousLocallyAuthored {
        tier: SelectedRecursiveTier,
        envelope: LinkProofEnvelope,
        replay: SelectedRecursiveLocalLinkReplay,
    },
}

/// One-shot local Link replay retained after the envelope itself moves into
/// the terminal package. It is neither cloneable nor serializable and becomes
/// useful only after binding to the exact decoded predecessor envelope.
pub struct SelectedRecursiveLocalLinkReplay {
    tier: SelectedRecursiveTier,
    replay: LocallyAuthoredLinkReplay,
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
    locally_authored_replay: Option<LocallyAuthoredLinkReplay>,
}

impl SelectedRecursiveLinkProof {
    /// Split a pipelined local result without cloning the proof envelope. The
    /// caller moves the envelope into durable terminal bytes and retains only
    /// the process-local replay capability for the next height.
    pub fn into_pipelined_parts(
        self,
    ) -> Result<
        (
            SelectedRecursiveTier,
            LinkProofEnvelope,
            SelectedRecursiveLocalLinkReplay,
        ),
        SelectedRecursiveProverError,
    > {
        let replay = self
            .locally_authored_replay
            .ok_or(SelectedRecursiveProverError::LocalReplayRequired { proof: "Link" })?;
        Ok((
            self.tier,
            self.envelope,
            SelectedRecursiveLocalLinkReplay {
                tier: self.tier,
                replay,
            },
        ))
    }
}

impl SelectedRecursiveLocalLinkReplay {
    /// Bind this one-shot capability to the exact envelope decoded from the
    /// in-memory terminal bytes. Tier mismatch or any durable/genesis value is
    /// rejected here; the lower preparation layer additionally authenticates
    /// the full envelope/class/transcript binding before folding.
    pub fn bind_decoded_predecessor(
        self,
        predecessor: SelectedRecursiveLinkPredecessor,
    ) -> Result<SelectedRecursiveLinkPredecessor, SelectedRecursiveProverError> {
        match predecessor {
            SelectedRecursiveLinkPredecessor::Previous { tier, envelope } if tier == self.tier => {
                Ok(SelectedRecursiveLinkPredecessor::PreviousLocallyAuthored {
                    tier,
                    envelope,
                    replay: self,
                })
            }
            SelectedRecursiveLinkPredecessor::Previous { tier, .. } => {
                Err(SelectedRecursiveProverError::LocalReplayTierMismatch {
                    expected: self.tier,
                    actual: tier,
                })
            }
            SelectedRecursiveLinkPredecessor::Genesis
            | SelectedRecursiveLinkPredecessor::PreviousLocallyAuthored { .. } => {
                Err(SelectedRecursiveProverError::LocalReplayBinding)
            }
        }
    }
}

const PIPELINE_BLOCK_LANE: u8 = 1 << 0;
const PIPELINE_LINK_LANE: u8 = 1 << 1;
const PIPELINE_EXCLUSIVE_B255_LANE: u8 = 1 << 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedHistoryPipelineLane {
    Block,
    Link,
    ExclusiveB255,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedHistorySessionBand {
    Small,
    B255,
}

impl SelectedHistorySessionBand {
    const fn for_tier(tier: SelectedRecursiveTier) -> Self {
        match tier {
            SelectedRecursiveTier::B8 | SelectedRecursiveTier::B32 | SelectedRecursiveTier::B64 => {
                Self::Small
            }
            SelectedRecursiveTier::B255 => Self::B255,
        }
    }

    const fn admits(self, tier: SelectedRecursiveTier) -> bool {
        matches!(
            (self, tier),
            (
                Self::Small,
                SelectedRecursiveTier::B8 | SelectedRecursiveTier::B32 | SelectedRecursiveTier::B64
            ) | (Self::B255, SelectedRecursiveTier::B255)
        )
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Small => "B8-B64",
            Self::B255 => "B255",
        }
    }
}

impl SelectedHistoryPipelineLane {
    const fn bit(self) -> u8 {
        match self {
            Self::Block => PIPELINE_BLOCK_LANE,
            Self::Link => PIPELINE_LINK_LANE,
            Self::ExclusiveB255 => PIPELINE_EXCLUSIVE_B255_LANE,
        }
    }

    const fn conflicts(self) -> u8 {
        match self {
            Self::Block => PIPELINE_BLOCK_LANE | PIPELINE_EXCLUSIVE_B255_LANE,
            Self::Link => PIPELINE_LINK_LANE | PIPELINE_EXCLUSIVE_B255_LANE,
            Self::ExclusiveB255 => u8::MAX,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Block => "Block",
            Self::Link => "Link",
            Self::ExclusiveB255 => "B255 Block/Link",
        }
    }
}

/// Owning permit for one proof lane inside a selected-history session. The
/// atomic bit is cleared during ordinary return, error propagation, or unwind.
struct SelectedHistoryPipelineLanePermit<'a> {
    active_lanes: &'a AtomicU8,
    bit: u8,
}

impl Drop for SelectedHistoryPipelineLanePermit<'_> {
    fn drop(&mut self) {
        self.active_lanes
            .fetch_and(!self.bit, AtomicOrdering::Release);
    }
}

/// One process-global tier-bound admission spanning a selected Block plus its
/// canonical m22 Link. B8-B64 use the only lane compatible with NativeB8;
/// B255 owns an exclusive profile.
///
/// Production callers must begin the session before reconstructing the
/// `noid_block` accepted-batch artifacts used to construct
/// [`SelectedRecursiveBlockJob`]. The single reservation then remains live
/// through both proof phases, excluding every unapproved overlap. The type is
/// intentionally not `Clone`. Its legacy `&mut self` methods serialize a
/// single height, while the explicit `*_pipelined` `&self` variants allow the
/// owning worker to overlap consecutive Block/Link lanes under this same
/// reservation. Dropping it releases admission during normal return, unwind,
/// or cancellation.
#[must_use = "dropping the session releases selected-history topology admission"]
pub struct SelectedHistoryProofSession {
    _reservation: ProofTopologyReservation,
    band: SelectedHistorySessionBand,
    active_pipeline_lanes: AtomicU8,
}

impl SelectedHistoryProofSession {
    pub fn admits_tier(&self, tier: SelectedRecursiveTier) -> bool {
        self.band.admits(tier)
    }

    fn require_tier(
        &self,
        tier: SelectedRecursiveTier,
    ) -> Result<(), SelectedRecursiveProverError> {
        if self.admits_tier(tier) {
            Ok(())
        } else {
            Err(SelectedRecursiveProverError::SessionTierMismatch {
                session: self.band.label(),
                requested: tier,
            })
        }
    }

    fn try_acquire_pipeline_lane(
        &self,
        lane: SelectedHistoryPipelineLane,
    ) -> Result<SelectedHistoryPipelineLanePermit<'_>, SelectedRecursiveProverError> {
        let bit = lane.bit();
        let conflicts = lane.conflicts();
        let mut active = self.active_pipeline_lanes.load(AtomicOrdering::Acquire);
        loop {
            if active & conflicts != 0 {
                return Err(SelectedRecursiveProverError::PipelineLaneBusy {
                    requested: lane.label(),
                });
            }
            match self.active_pipeline_lanes.compare_exchange_weak(
                active,
                active | bit,
                AtomicOrdering::AcqRel,
                AtomicOrdering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(SelectedHistoryPipelineLanePermit {
                        active_lanes: &self.active_pipeline_lanes,
                        bit,
                    });
                }
                Err(observed) => active = observed,
            }
        }
    }

    fn with_pipeline_lane<T: Send>(
        &self,
        lane: SelectedHistoryPipelineLane,
        cpu_stage: SelectedHistoryCpuStage,
        prove: impl FnOnce() -> Result<T, SelectedRecursiveProverError> + Send,
    ) -> Result<T, SelectedRecursiveProverError> {
        let _permit = self.try_acquire_pipeline_lane(lane)?;
        install_selected_history_cpu(cpu_stage, prove)
            .map_err(SelectedRecursiveProverError::CpuBudget)?
    }

    fn block_pipeline_lane(
        &self,
        job: &SelectedRecursiveBlockJob,
    ) -> Result<SelectedHistoryPipelineLane, SelectedRecursiveProverError> {
        let tier = selected_recursive_tier(job.artifacts.live_authorization_count())?;
        self.require_tier(tier)?;
        Ok(Self::pipeline_lane_for_tier(
            tier,
            SelectedHistoryPipelineLane::Block,
        ))
    }

    fn link_pipeline_lane(
        &self,
        job: &SelectedRecursiveLinkJob,
    ) -> Result<SelectedHistoryPipelineLane, SelectedRecursiveProverError> {
        self.require_tier(job.current_block.tier)?;
        Ok(Self::pipeline_lane_for_tier(
            job.current_block.tier,
            SelectedHistoryPipelineLane::Link,
        ))
    }

    fn pipeline_lane_for_tier(
        tier: SelectedRecursiveTier,
        ordinary_lane: SelectedHistoryPipelineLane,
    ) -> SelectedHistoryPipelineLane {
        if tier == SelectedRecursiveTier::B255 {
            SelectedHistoryPipelineLane::ExclusiveB255
        } else {
            ordinary_lane
        }
    }

    /// Prove the selected Block while reusing this session's tier-bound
    /// reservation. No second governor admission is attempted.
    pub fn prove_block(
        &mut self,
        classes: &SelectedRecursiveBlockClasses<'_>,
        job: SelectedRecursiveBlockJob,
    ) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
        self.require_tier(selected_recursive_tier(
            job.artifacts.live_authorization_count(),
        )?)?;
        prove_selected_recursive_block_in_reserved_session(classes, job)
    }

    /// Embedded compact-relation Block path. Compatibility sources may
    /// return `None`, in which case this preserves the full-CSR offline path.
    pub fn prove_block_with_matrices<S: SelectedRecursiveMatrixSource>(
        &mut self,
        classes: &SelectedRecursiveBlockClasses<'_>,
        job: SelectedRecursiveBlockJob,
        matrices: &mut S,
    ) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
        self.require_tier(selected_recursive_tier(
            job.artifacts.live_authorization_count(),
        )?)?;
        prove_selected_recursive_block_in_reserved_session_with_matrices(classes, job, matrices)
    }

    /// Prove the following Link while retaining the same reservation acquired
    /// before Block artifact reconstruction.
    pub fn prove_link<S: SelectedRecursiveMatrixSource>(
        &mut self,
        classes: &SelectedRecursiveLinkClasses<'_>,
        job: SelectedRecursiveLinkJob,
        matrices: &mut S,
    ) -> Result<SelectedRecursiveLinkProof, SelectedRecursiveProverError> {
        self.require_tier(job.current_block.tier)?;
        prove_selected_recursive_link_in_reserved_session(classes, job, matrices, false)
    }

    /// Pipelined Block variant sharing the one held reservation through
    /// `&self`: the history worker's block lane may prove height N+1 while
    /// its link lane proves height N. The governor is not re-entered here;
    /// pipeline depth belongs to the worker that owns this session.
    pub fn prove_block_pipelined(
        &self,
        classes: &SelectedRecursiveBlockClasses<'_>,
        link_classes: &SelectedRecursiveLinkClasses<'_>,
        job: SelectedRecursiveBlockJob,
    ) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
        let lane = self.block_pipeline_lane(&job)?;
        self.with_pipeline_lane(lane, SelectedHistoryCpuStage::Block, || {
            prove_selected_recursive_block_in_reserved_session_locally_authored(
                classes,
                link_classes,
                job,
            )
        })
    }

    /// Pipelined compact-relation twin of [`Self::prove_block_with_matrices`].
    pub fn prove_block_pipelined_with_matrices<S: SelectedRecursiveMatrixSource + Send>(
        &self,
        classes: &SelectedRecursiveBlockClasses<'_>,
        link_classes: &SelectedRecursiveLinkClasses<'_>,
        job: SelectedRecursiveBlockJob,
        matrices: &mut S,
    ) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
        let lane = self.block_pipeline_lane(&job)?;
        self.with_pipeline_lane(lane, SelectedHistoryCpuStage::Block, || {
            prove_selected_recursive_block_in_reserved_session_with_matrices_locally_authored(
                classes,
                link_classes,
                job,
                matrices,
            )
        })
    }

    /// Pipelined Link variant of [`Self::prove_link`]; see
    /// [`Self::prove_block_pipelined`] for the shared-reservation contract.
    pub fn prove_link_pipelined<S: SelectedRecursiveMatrixSource + Send>(
        &self,
        classes: &SelectedRecursiveLinkClasses<'_>,
        job: SelectedRecursiveLinkJob,
        matrices: &mut S,
    ) -> Result<SelectedRecursiveLinkProof, SelectedRecursiveProverError> {
        if job.current_block.locally_authored_replay.is_none() {
            return Err(SelectedRecursiveProverError::LocalReplayRequired { proof: "Block" });
        }
        let lane = self.link_pipeline_lane(&job)?;
        self.with_pipeline_lane(lane, SelectedHistoryCpuStage::Link, || {
            prove_selected_recursive_link_in_reserved_session(classes, job, matrices, true)
        })
    }
}

/// Acquire the tier-bound selected-history envelope from the process-wide
/// topology gate. Call this before reconstructing artifacts that feed
/// [`SelectedHistoryProofSession::prove_block`].
pub fn begin_selected_history_proof_session(
    tier: SelectedRecursiveTier,
) -> Result<SelectedHistoryProofSession, SelectedRecursiveProverError> {
    begin_selected_history_proof_session_with_gate(&ProofTopologyGate::global(), tier)
}

fn begin_selected_history_proof_session_with_gate(
    gate: &ProofTopologyGate,
    tier: SelectedRecursiveTier,
) -> Result<SelectedHistoryProofSession, SelectedRecursiveProverError> {
    Ok(SelectedHistoryProofSession {
        _reservation: gate.try_admit_selected_history_session(tier.capacity())?,
        band: SelectedHistorySessionBand::for_tier(tier),
        active_pipeline_lanes: AtomicU8::new(0),
    })
}

#[cfg(test)]
fn begin_selected_history_proof_session_for_tests(
    gate: &ProofTopologyGate,
    tier: SelectedRecursiveTier,
) -> Result<SelectedHistoryProofSession, SelectedRecursiveProverError> {
    begin_selected_history_proof_session_with_gate(gate, tier)
}

/// Exclusive startup authority for materializing the embedded registry and
/// compact B8 matrix bank before P2P/RPC can expose competing proof work.
#[must_use = "dropping the session releases startup proof-topology admission"]
pub struct SelectedHistoryPrewarmSession {
    _reservation: ProofTopologyReservation,
}

pub fn begin_selected_history_prewarm_session(
) -> Result<SelectedHistoryPrewarmSession, SelectedRecursiveProverError> {
    let gate = ProofTopologyGate::global();
    Ok(SelectedHistoryPrewarmSession {
        _reservation: gate.try_admit_selected_history_prewarm()?,
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

    /// Mutable borrow for resident claim evaluation; same RAII rules as
    /// [`Self::matrix`].
    pub(crate) fn matrix_mut(&mut self) -> &mut FieldR1cs {
        self.matrix
            .as_mut()
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

    /// Own a transient CSR decoded from immutable bytes whose structural
    /// digest was already established by the executable-embedded compact
    /// bank. No release callback is needed: dropping this wrapper simply
    /// returns the transient CSR memory to the allocator.
    pub(crate) fn from_authenticated_owned(
        matrix: FieldR1cs,
        _established_digest: [u8; 32],
    ) -> Self {
        Self {
            matrix: Some(matrix),
            release_callback: None,
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

    /// Return an already-authenticated immutable compact relation when the
    /// source can provide one. Disk/rebuild compatibility sources use the
    /// default and continue through [`Self::load_matrix`]; the executable
    /// embedded bank overrides this so production Link folding never decodes
    /// transient CSR arrays.
    fn load_compact_matrix(
        &mut self,
        _request: SelectedRecursiveMatrixRequest,
    ) -> Result<Option<Arc<CompactFieldR1cs>>, Self::Error> {
        Ok(None)
    }

    fn load_matrix(
        &mut self,
        request: SelectedRecursiveMatrixRequest,
    ) -> Result<LoadedSelectedRecursiveMatrix, Self::Error>;
}

#[derive(Debug)]
pub enum SelectedRecursiveProverError {
    /// A caller requested identities from the worker-owned immutable registry
    /// before startup authentication/materialization completed.
    RegistryNotPreloaded,
    /// A second proof tried to enter an already-active session lane, or any
    /// proof tried to overlap the exclusive B255 Block/Link lane.
    PipelineLaneBusy {
        requested: &'static str,
    },
    /// A small (B8-B64) session reached a B255 successor, or a B255-exclusive
    /// session was reused for a smaller successor instead of draining first.
    SessionTierMismatch {
        session: &'static str,
        requested: SelectedRecursiveTier,
    },
    /// The process owner did not configure the common fixed proof pool before
    /// exposing a pipelined Block/Link entry point.
    CpuBudget(ProcessCpuBudgetError),
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
    LocalReplayRequired {
        proof: &'static str,
    },
    LocalReplayTierMismatch {
        expected: SelectedRecursiveTier,
        actual: SelectedRecursiveTier,
    },
    LocalReplayBinding,
    MatrixLoad {
        kind: SelectedRecursiveMatrixKind,
        detail: String,
    },
    LinkPreparation(SplitLinkPreparationError),
    LinkPreparationRejected,
    /// Another proof kernel owns an incompatible process topology slot.
    ProofStageBusy,
    /// Internal code requested a class outside the canonical proof topology.
    ProofTopologyInvariant(&'static str),
    RecursiveAssemblyRejected,
    LinkAssemblyRejected,
    BlockProof(BlockProofError),
    LinkProof(LinkProofError),
}

impl core::fmt::Display for SelectedRecursiveProverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RegistryNotPreloaded => {
                write!(f, "selected recursive prover registry is not preloaded")
            }
            Self::PipelineLaneBusy { requested } => {
                write!(f, "selected-history {requested} pipeline lane is already active")
            }
            Self::SessionTierMismatch { session, requested } => write!(
                f,
                "selected-history {session} session cannot prove {requested:?}; drain and reacquire admission"
            ),
            Self::CpuBudget(source) => {
                write!(f, "selected-history process CPU admission failed: {source}")
            }
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
            Self::LocalReplayRequired { proof } => {
                write!(f, "pipelined {proof} proof has no local replay capsule")
            }
            Self::LocalReplayTierMismatch { expected, actual } => write!(
                f,
                "local Link replay tier {expected:?} does not match decoded predecessor {actual:?}"
            ),
            Self::LocalReplayBinding => {
                write!(f, "local Link replay cannot bind this predecessor")
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
            Self::ProofStageBusy => {
                f.write_str("selected recursive proof deferred by an active proof stage")
            }
            Self::ProofTopologyInvariant(message) => {
                write!(f, "selected recursive proof topology invariant: {message}")
            }
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

impl From<ProcessCpuBudgetError> for SelectedRecursiveProverError {
    fn from(value: ProcessCpuBudgetError) -> Self {
        Self::CpuBudget(value)
    }
}

impl From<ProofTopologyAdmissionError> for SelectedRecursiveProverError {
    fn from(value: ProofTopologyAdmissionError) -> Self {
        match value {
            ProofTopologyAdmissionError::Busy => Self::ProofStageBusy,
            ProofTopologyAdmissionError::NonCanonicalNativeUserTxCount { .. } => {
                Self::ProofTopologyInvariant("recursive path requested a native transaction class")
            }
            ProofTopologyAdmissionError::NonCanonicalRecursiveTier { .. } => {
                Self::ProofTopologyInvariant("non-canonical recursive tier reached admission")
            }
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

enum LoadedSelectedRecursiveFoldMatrix {
    Resident(LoadedSelectedRecursiveMatrix),
    Compact(Arc<CompactFieldR1cs>),
}

fn load_selected_recursive_fold_matrix<S: SelectedRecursiveMatrixSource>(
    source: &mut S,
    request: SelectedRecursiveMatrixRequest,
) -> Result<LoadedSelectedRecursiveFoldMatrix, S::Error> {
    if let Some(matrix) = source.load_compact_matrix(request)? {
        return Ok(LoadedSelectedRecursiveFoldMatrix::Compact(matrix));
    }
    source
        .load_matrix(request)
        .map(LoadedSelectedRecursiveFoldMatrix::Resident)
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
    prepare_previous: impl FnOnce(
        PreviousPhase,
        &LoadedSelectedRecursiveFoldMatrix,
    ) -> Result<BlockPhase, PhaseError>,
    prepare_block: impl FnOnce(
        BlockPhase,
        &LoadedSelectedRecursiveFoldMatrix,
    ) -> Result<Prepared, PhaseError>,
) -> Result<Prepared, SequentialMatrixPhaseError<S::Error, PhaseError>>
where
    S: SelectedRecursiveMatrixSource,
{
    let previous_load_started = Instant::now();
    let previous_matrix =
        load_selected_recursive_fold_matrix(source, previous_request).map_err(|source| {
            SequentialMatrixPhaseError::Load {
                request: previous_request,
                source,
            }
        })?;
    let previous_load_ms = previous_load_started.elapsed().as_millis() as u64;
    let previous_prepare_started = Instant::now();
    let block_phase = prepare_previous(previous_phase, &previous_matrix)
        .map_err(SequentialMatrixPhaseError::Phase)?;
    let previous_auth_and_fold_ms = previous_prepare_started.elapsed().as_millis() as u64;
    drop(previous_matrix);

    let block_load_started = Instant::now();
    let block_matrix =
        load_selected_recursive_fold_matrix(source, block_request).map_err(|source| {
            SequentialMatrixPhaseError::Load {
                request: block_request,
                source,
            }
        })?;
    let block_load_ms = block_load_started.elapsed().as_millis() as u64;
    let block_prepare_started = Instant::now();
    let prepared =
        prepare_block(block_phase, &block_matrix).map_err(SequentialMatrixPhaseError::Phase)?;
    let block_auth_and_fold_ms = block_prepare_started.elapsed().as_millis() as u64;
    drop(block_matrix);
    tracing::info!(
        previous_kind = ?previous_request.kind(),
        block_kind = ?block_request.kind(),
        previous_load_ms,
        previous_auth_and_fold_ms,
        block_load_ms,
        block_auth_and_fold_ms,
        "selected-history Link sequential matrix phases"
    );
    Ok(prepared)
}

/// Author one production selected recursive Block proof.
///
/// The process-global topology gate is acquired before native proof replay, ghost
/// generation, or m22+ assembly. Thus a coinbase-only block still reserves B8
/// and this background job cannot overlap the miner's native proof worker.
pub fn prove_selected_recursive_block(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    prove_selected_recursive_block_with_gate(classes, job, &ProofTopologyGate::global())
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
    prove_selected_recursive_link_with_gate(classes, job, matrices, &ProofTopologyGate::global())
}

fn prove_selected_recursive_link_with_gate<S: SelectedRecursiveMatrixSource>(
    classes: &SelectedRecursiveLinkClasses<'_>,
    job: SelectedRecursiveLinkJob,
    matrices: &mut S,
    gate: &ProofTopologyGate,
) -> Result<SelectedRecursiveLinkProof, SelectedRecursiveProverError> {
    let _topology_reservation = gate.try_admit_recursive_link()?;
    prove_selected_recursive_link_in_reserved_session(classes, job, matrices, false)
}

/// Cryptographic Link body entered only after a standalone or session-level
/// reservation has been acquired. Keep topology admission out of this path so
/// a Block+Link session never re-enters or reclassifies the typed ledger.
fn prove_selected_recursive_link_in_reserved_session<S: SelectedRecursiveMatrixSource>(
    classes: &SelectedRecursiveLinkClasses<'_>,
    job: SelectedRecursiveLinkJob,
    matrices: &mut S,
    capture_locally_authored_link: bool,
) -> Result<SelectedRecursiveLinkProof, SelectedRecursiveProverError> {
    let link_body_started = Instant::now();
    let SelectedRecursiveLinkJob {
        predecessor,
        current_block,
    } = job;
    let SelectedRecursiveBlockProof {
        tier: current_tier,
        envelope: current_block_envelope,
        locally_authored_replay: current_block_replay,
    } = current_block;
    let class = classes.get(current_tier);
    validate_link_class_binding(
        current_tier.slot(),
        current_tier.capacity(),
        class.slot(),
        class.ladder()[class.slot()].tier,
    )?;

    let (
        previous_envelope_owned,
        previous_slot,
        genesis,
        previous_request,
        previous_local_replay,
        previous_auth_mode,
    ) = match predecessor {
        SelectedRecursiveLinkPredecessor::Genesis => (
            None,
            0usize,
            true,
            SelectedRecursiveMatrixRequest {
                kind: SelectedRecursiveMatrixKind::GenesisLink,
                shape: class.shape,
                statement_digest: class.genesis_digest,
            },
            None,
            "genesis_full_verify",
        ),
        SelectedRecursiveLinkPredecessor::Previous { tier, envelope } => {
            let previous_class = classes.get(tier);
            validate_link_class_binding(
                tier.slot(),
                tier.capacity(),
                previous_class.slot(),
                previous_class.ladder()[previous_class.slot()].tier,
            )?;
            (
                Some(envelope),
                tier.slot(),
                false,
                SelectedRecursiveMatrixRequest {
                    kind: SelectedRecursiveMatrixKind::PreviousLink(tier),
                    shape: previous_class.shape,
                    statement_digest: classes.link_class_digests[tier.slot()],
                },
                None,
                "durable_full_verify",
            )
        }
        SelectedRecursiveLinkPredecessor::PreviousLocallyAuthored {
            tier,
            envelope,
            replay,
        } => {
            let SelectedRecursiveLocalLinkReplay {
                tier: replay_tier,
                replay,
            } = replay;
            if replay_tier != tier || !capture_locally_authored_link {
                return Err(SelectedRecursiveProverError::LocalReplayBinding);
            }
            let previous_class = classes.get(tier);
            validate_link_class_binding(
                tier.slot(),
                tier.capacity(),
                previous_class.slot(),
                previous_class.ladder()[previous_class.slot()].tier,
            )?;
            (
                Some(envelope),
                tier.slot(),
                false,
                SelectedRecursiveMatrixRequest {
                    kind: SelectedRecursiveMatrixKind::PreviousLink(tier),
                    shape: previous_class.shape,
                    statement_digest: classes.link_class_digests[tier.slot()],
                },
                Some(replay),
                "local_capsule",
            )
        }
    };
    if capture_locally_authored_link && current_block_replay.is_none() {
        return Err(SelectedRecursiveProverError::LocalReplayRequired { proof: "Block" });
    }
    if !capture_locally_authored_link && current_block_replay.is_some() {
        return Err(SelectedRecursiveProverError::LocalReplayBinding);
    }
    let block_auth_mode = if current_block_replay.is_some() {
        "local_capsule"
    } else {
        "full_verify"
    };
    let previous_envelope = previous_envelope_owned
        .as_ref()
        .unwrap_or_else(|| class.genesis_envelope());
    let block_request = SelectedRecursiveMatrixRequest {
        kind: SelectedRecursiveMatrixKind::CurrentBlock(current_tier),
        shape: class.ladder()[class.slot()].b_shape,
        statement_digest: class.ladder()[class.slot()].b_digest,
    };
    let preflight_started = Instant::now();
    let previous_phase = begin_split_link_native_preparation(
        class,
        SplitLinkTraceInput {
            prev: previous_envelope,
            prev_slot: previous_slot,
            genesis,
            link_class_digests: classes.link_class_digests.to_vec(),
            link_post_commit_class_digests: classes.link_post_commit_class_digests.to_vec(),
            block: &current_block_envelope,
        },
    )
    .map_err(SelectedRecursiveProverError::LinkPreparation)?;
    let preflight_ms = preflight_started.elapsed().as_millis() as u64;

    let matrix_phases_started = Instant::now();
    let prepare_matrices = AssertUnwindSafe(|| {
        run_sequential_matrix_phases(
            matrices,
            previous_request,
            block_request,
            previous_phase,
            |phase, matrix| match (matrix, previous_local_replay) {
                (LoadedSelectedRecursiveFoldMatrix::Compact(matrix), Some(replay)) => {
                    phase.prepare_previous_link_compact_locally_authored(matrix, replay)
                }
                (LoadedSelectedRecursiveFoldMatrix::Resident(matrix), Some(replay)) => {
                    phase.prepare_previous_link_locally_authored(matrix.matrix(), replay)
                }
                (LoadedSelectedRecursiveFoldMatrix::Compact(matrix), None) => {
                    phase.prepare_previous_link_compact(matrix)
                }
                (LoadedSelectedRecursiveFoldMatrix::Resident(matrix), None) => {
                    phase.prepare_previous_link(matrix.matrix())
                }
            },
            |phase, matrix| match (matrix, current_block_replay) {
                (LoadedSelectedRecursiveFoldMatrix::Compact(matrix), Some(replay)) => {
                    phase.prepare_current_block_compact_locally_authored(matrix, replay)
                }
                (LoadedSelectedRecursiveFoldMatrix::Resident(matrix), Some(replay)) => {
                    phase.prepare_current_block_locally_authored(matrix.matrix(), replay)
                }
                (LoadedSelectedRecursiveFoldMatrix::Compact(matrix), None) => {
                    phase.prepare_current_block_compact(matrix)
                }
                (LoadedSelectedRecursiveFoldMatrix::Resident(matrix), None) => {
                    phase.prepare_current_block(matrix.matrix())
                }
            },
        )
        .map_err(map_sequential_link_error)
    });
    let prepared = catch_unwind(prepare_matrices)
        .map_err(|_| SelectedRecursiveProverError::LinkPreparationRejected)??;
    let matrix_phases_ms = matrix_phases_started.elapsed().as_millis() as u64;

    // The embedded source returns another Arc to the already authenticated
    // current Link relation.  Holding it across witness assembly does not
    // decode or duplicate matrix storage; compatibility sources return None
    // and retain the full-CSR offline path below.
    let output_request = SelectedRecursiveMatrixRequest {
        kind: SelectedRecursiveMatrixKind::PreviousLink(current_tier),
        shape: class.shape,
        statement_digest: classes.link_class_digests[current_tier.slot()],
    };
    let force_rehash = force_matrix_rehash_for_diagnostics();
    let output_compact = if !force_rehash {
        matrices
            .load_compact_matrix(output_request)
            .map_err(|source| SelectedRecursiveProverError::MatrixLoad {
                kind: output_request.kind,
                detail: source.to_string(),
            })?
    } else {
        None
    };

    // Both transient child matrices are gone before the canonical m22 Link trace and
    // proof are allocated. Internal assertion failures remain fail-closed at
    // this production boundary.
    let assemble_and_prove = AssertUnwindSafe(|| {
        let assemble_started = Instant::now();
        let proof = if let Some(relation) = output_compact {
            let matrix_storage = relation.storage_name();
            let matrix_resident_bytes = relation.resident_heap_payload_len();
            let built = prepared.assemble_witness_only_established(&relation)?;
            let assemble_ms = assemble_started.elapsed().as_millis() as u64;
            let prove_started = Instant::now();
            let proof = if capture_locally_authored_link {
                prove_built_split_link_compact_locally_authored(class, &relation, &built)
                    .map(|(envelope, replay)| (envelope, Some(replay)))
            } else {
                let mut challenger = FsLaneChallenger::new(b"history-link-v0");
                prove_built_split_link_compact(class, &relation, &built, &mut challenger)
                    .map(|envelope| (envelope, None))
            };
            let prove_ms = prove_started.elapsed().as_millis() as u64;
            tracing::info!(
                tier = ?current_tier,
                previous_auth_mode,
                block_auth_mode,
                preflight_ms,
                matrix_phases_ms,
                assemble_ms,
                prove_ms,
                compact_relation = true,
                matrix_storage,
                matrix_resident_bytes,
                ok = proof.is_ok(),
                "selected-history m22 Link body phases"
            );
            proof
        } else {
            let built = if force_rehash {
                prepared.assemble()
            } else {
                prepared.assemble_established()
            };
            let assemble_ms = assemble_started.elapsed().as_millis() as u64;
            let prove_started = Instant::now();
            let proof = if capture_locally_authored_link {
                prove_built_split_link_locally_authored(class, &built)
                    .map(|(envelope, replay)| (envelope, Some(replay)))
            } else {
                let mut challenger = FsLaneChallenger::new(b"history-link-v0");
                prove_built_split_link(class, &built, &mut challenger)
                    .map(|envelope| (envelope, None))
            };
            let prove_ms = prove_started.elapsed().as_millis() as u64;
            tracing::info!(
                tier = ?current_tier,
                previous_auth_mode,
                block_auth_mode,
                preflight_ms,
                matrix_phases_ms,
                assemble_ms,
                prove_ms,
                compact_relation = false,
                ok = proof.is_ok(),
                "selected-history m22 Link body phases"
            );
            proof
        };
        proof
    });
    let (envelope, locally_authored_replay) = catch_unwind(assemble_and_prove)
        .map_err(|_| SelectedRecursiveProverError::LinkAssemblyRejected)?
        .map_err(SelectedRecursiveProverError::LinkProof)?;
    let proof = SelectedRecursiveLinkProof {
        tier: current_tier,
        envelope,
        locally_authored_replay,
    };
    tracing::info!(
        tier = ?current_tier,
        previous_auth_mode,
        block_auth_mode,
        link_body_ms = link_body_started.elapsed().as_millis() as u64,
        "selected-history m22 Link body complete"
    );
    Ok(proof)
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

fn prove_selected_recursive_block_with_gate(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob,
    gate: &ProofTopologyGate,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let tier = preflight_selected_recursive_block(classes, &job)?;
    let _topology_reservation = gate.try_admit_recursive_tier(tier.capacity())?;
    prove_selected_recursive_block_after_admission(classes, job, tier, None)
}

/// Selected Block entry for an already-admitted history session. The caller
/// owns the session topology slot before artifact reconstruction, so this path
/// must never attempt tier-local admission.
fn prove_selected_recursive_block_in_reserved_session(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let tier = preflight_selected_recursive_block(classes, &job)?;
    prove_selected_recursive_block_after_admission(classes, job, tier, None)
}

/// Pipelined Block authoring retains an opaque replay capsule bound to the
/// exact hosted Link class. It is consumed by the immediately following Link
/// stage; standalone and durable APIs never mint this authority.
fn prove_selected_recursive_block_in_reserved_session_locally_authored(
    classes: &SelectedRecursiveBlockClasses<'_>,
    link_classes: &SelectedRecursiveLinkClasses<'_>,
    job: SelectedRecursiveBlockJob,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let tier = preflight_selected_recursive_block(classes, &job)?;
    prove_selected_recursive_block_after_admission(classes, job, tier, Some(link_classes.get(tier)))
}

fn prove_selected_recursive_block_in_reserved_session_with_matrices<
    S: SelectedRecursiveMatrixSource,
>(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob,
    matrices: &mut S,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let tier = preflight_selected_recursive_block(classes, &job)?;
    if force_matrix_rehash_for_diagnostics() {
        return prove_selected_recursive_block_after_admission(classes, job, tier, None);
    }
    let class = classes.get(tier);
    let request = SelectedRecursiveMatrixRequest {
        kind: SelectedRecursiveMatrixKind::CurrentBlock(tier),
        shape: class.shape,
        statement_digest: class.class_statement_digest.get().copied().ok_or(
            SelectedRecursiveProverError::ClassIdentity {
                tier: tier.capacity(),
                source: BlockProofError::UnfrozenClass,
            },
        )?,
    };
    match matrices.load_compact_matrix(request).map_err(|source| {
        SelectedRecursiveProverError::MatrixLoad {
            kind: request.kind,
            detail: source.to_string(),
        }
    })? {
        Some(relation) => prove_selected_recursive_block_after_admission_compact(
            classes, job, tier, relation, None,
        ),
        None => prove_selected_recursive_block_after_admission(classes, job, tier, None),
    }
}

fn prove_selected_recursive_block_in_reserved_session_with_matrices_locally_authored<
    S: SelectedRecursiveMatrixSource,
>(
    classes: &SelectedRecursiveBlockClasses<'_>,
    link_classes: &SelectedRecursiveLinkClasses<'_>,
    job: SelectedRecursiveBlockJob,
    matrices: &mut S,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let tier = preflight_selected_recursive_block(classes, &job)?;
    let link_class = link_classes.get(tier);
    if force_matrix_rehash_for_diagnostics() {
        return prove_selected_recursive_block_after_admission(
            classes,
            job,
            tier,
            Some(link_class),
        );
    }
    let class = classes.get(tier);
    let request = SelectedRecursiveMatrixRequest {
        kind: SelectedRecursiveMatrixKind::CurrentBlock(tier),
        shape: class.shape,
        statement_digest: class.class_statement_digest.get().copied().ok_or(
            SelectedRecursiveProverError::ClassIdentity {
                tier: tier.capacity(),
                source: BlockProofError::UnfrozenClass,
            },
        )?,
    };
    match matrices.load_compact_matrix(request).map_err(|source| {
        SelectedRecursiveProverError::MatrixLoad {
            kind: request.kind,
            detail: source.to_string(),
        }
    })? {
        Some(relation) => prove_selected_recursive_block_after_admission_compact(
            classes,
            job,
            tier,
            relation,
            Some(link_class),
        ),
        None => {
            prove_selected_recursive_block_after_admission(classes, job, tier, Some(link_class))
        }
    }
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
    locally_authored_link_class: Option<&SplitLinkClass>,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let block_body_started = Instant::now();
    let ghost_started = Instant::now();
    let ghost = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
        .map_err(|_| SelectedRecursiveProverError::GhostProofGeneration)?;
    let ghost_ms = ghost_started.elapsed().as_millis() as u64;

    let class = classes.get(tier);
    let build_and_prove = AssertUnwindSafe(|| match tier {
        SelectedRecursiveTier::B8 => {
            build_and_prove_selected::<8>(class, locally_authored_link_class, job, ghost)
        }
        SelectedRecursiveTier::B32 => {
            build_and_prove_selected::<32>(class, locally_authored_link_class, job, ghost)
        }
        SelectedRecursiveTier::B64 => {
            build_and_prove_selected::<64>(class, locally_authored_link_class, job, ghost)
        }
        SelectedRecursiveTier::B255 => {
            build_and_prove_selected::<255>(class, locally_authored_link_class, job, ghost)
        }
    });
    let (envelope, locally_authored_replay) = catch_unwind(build_and_prove)
        .map_err(|_| SelectedRecursiveProverError::RecursiveAssemblyRejected)??;
    tracing::info!(
        tier = ?tier,
        ghost_ms,
        block_body_ms = block_body_started.elapsed().as_millis() as u64,
        "selected-history Block body complete"
    );
    Ok(SelectedRecursiveBlockProof {
        tier,
        envelope,
        locally_authored_replay,
    })
}

fn prove_selected_recursive_block_after_admission_compact(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob,
    tier: SelectedRecursiveTier,
    relation: Arc<CompactFieldR1cs>,
    locally_authored_link_class: Option<&SplitLinkClass>,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let block_body_started = Instant::now();
    let ghost_started = Instant::now();
    let ghost = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
        .map_err(|_| SelectedRecursiveProverError::GhostProofGeneration)?;
    let ghost_ms = ghost_started.elapsed().as_millis() as u64;

    let class = classes.get(tier);
    let build_and_prove = AssertUnwindSafe(|| match tier {
        SelectedRecursiveTier::B8 => build_and_prove_selected_compact::<8>(
            class,
            locally_authored_link_class,
            job,
            ghost,
            &relation,
        ),
        SelectedRecursiveTier::B32 => build_and_prove_selected_compact::<32>(
            class,
            locally_authored_link_class,
            job,
            ghost,
            &relation,
        ),
        SelectedRecursiveTier::B64 => build_and_prove_selected_compact::<64>(
            class,
            locally_authored_link_class,
            job,
            ghost,
            &relation,
        ),
        SelectedRecursiveTier::B255 => build_and_prove_selected_compact::<255>(
            class,
            locally_authored_link_class,
            job,
            ghost,
            &relation,
        ),
    });
    let (envelope, locally_authored_replay) = catch_unwind(build_and_prove)
        .map_err(|_| SelectedRecursiveProverError::RecursiveAssemblyRejected)??;
    tracing::info!(
        tier = ?tier,
        ghost_ms,
        compact_relation = true,
        matrix_storage = relation.storage_name(),
        matrix_resident_bytes = relation.resident_heap_payload_len(),
        block_body_ms = block_body_started.elapsed().as_millis() as u64,
        "selected-history Block body complete"
    );
    Ok(SelectedRecursiveBlockProof {
        tier,
        envelope,
        locally_authored_replay,
    })
}

fn build_and_prove_selected<const TIER: usize>(
    class: &BlockClass,
    locally_authored_link_class: Option<&SplitLinkClass>,
    job: SelectedRecursiveBlockJob,
    ghost: ZkAuthorizationProof,
) -> Result<(BlockProofEnvelope, Option<LocallyAuthoredBlockReplay>), SelectedRecursiveProverError>
{
    let parts_started = Instant::now();
    let (
        start_accumulator,
        end_accumulator,
        component_inputs,
        component_proof,
        selected_authorization_proofs,
    ) = job.artifacts.into_recursive_builder_parts();
    let parts_ms = parts_started.elapsed().as_millis() as u64;
    let input_started = Instant::now();
    let input = SelectedZkBlockInput::<TIER>::try_new(
        &start_accumulator,
        &end_accumulator,
        &component_inputs,
        &component_proof,
        selected_authorization_proofs,
        ghost,
    )
    .map_err(SelectedRecursiveProverError::Input)?;
    let input_ms = input_started.elapsed().as_millis() as u64;
    let build_started = Instant::now();
    let built = if force_matrix_rehash_for_diagnostics() {
        build_selected_zk_block_proof_trace(class, input)
    } else {
        build_selected_zk_block_proof_trace_established(class, input)
    };
    let build_ms = build_started.elapsed().as_millis() as u64;
    let prove_started = Instant::now();
    let proof = match locally_authored_link_class {
        Some(link_class) => prove_built_block_locally_authored(class, link_class, &built)
            .map(|(envelope, replay)| (envelope, Some(replay))),
        None => {
            let mut challenger = FsLaneChallenger::new(BLOCK_PROOF_TRANSCRIPT_DOMAIN);
            prove_built_block(class, &built, &mut challenger).map(|envelope| (envelope, None))
        }
    }
    .map_err(SelectedRecursiveProverError::BlockProof);
    let prove_ms = prove_started.elapsed().as_millis() as u64;
    tracing::info!(
        tier = TIER,
        parts_ms,
        input_ms,
        build_ms,
        prove_ms,
        ok = proof.is_ok(),
        "selected-history Block build/prove phases"
    );
    proof
}

fn build_and_prove_selected_compact<const TIER: usize>(
    class: &BlockClass,
    locally_authored_link_class: Option<&SplitLinkClass>,
    job: SelectedRecursiveBlockJob,
    ghost: ZkAuthorizationProof,
    relation: &CompactFieldR1cs,
) -> Result<(BlockProofEnvelope, Option<LocallyAuthoredBlockReplay>), SelectedRecursiveProverError>
{
    let parts_started = Instant::now();
    let (
        start_accumulator,
        end_accumulator,
        component_inputs,
        component_proof,
        selected_authorization_proofs,
    ) = job.artifacts.into_recursive_builder_parts();
    let parts_ms = parts_started.elapsed().as_millis() as u64;
    let input_started = Instant::now();
    let input = SelectedZkBlockInput::<TIER>::try_new(
        &start_accumulator,
        &end_accumulator,
        &component_inputs,
        &component_proof,
        selected_authorization_proofs,
        ghost,
    )
    .map_err(SelectedRecursiveProverError::Input)?;
    let input_ms = input_started.elapsed().as_millis() as u64;
    let build_started = Instant::now();
    let built = build_selected_zk_block_proof_witness_established(class, input, relation)
        .map_err(SelectedRecursiveProverError::BlockProof)?;
    let build_ms = build_started.elapsed().as_millis() as u64;
    let prove_started = Instant::now();
    let proof = match locally_authored_link_class {
        Some(link_class) => {
            prove_built_block_compact_locally_authored(class, link_class, relation, &built)
                .map(|(envelope, replay)| (envelope, Some(replay)))
        }
        None => {
            let mut challenger = FsLaneChallenger::new(BLOCK_PROOF_TRANSCRIPT_DOMAIN);
            prove_built_block_compact(class, relation, &built, &mut challenger)
                .map(|envelope| (envelope, None))
        }
    }
    .map_err(SelectedRecursiveProverError::BlockProof);
    let prove_ms = prove_started.elapsed().as_millis() as u64;
    tracing::info!(
        tier = TIER,
        parts_ms,
        input_ms,
        build_ms,
        prove_ms,
        compact_relation = true,
        matrix_storage = relation.storage_name(),
        matrix_resident_bytes = relation.resident_heap_payload_len(),
        ok = proof.is_ok(),
        "selected-history Block build/prove phases"
    );
    proof
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
    fn matrix_rehash_override_is_disabled_for_optimized_binaries() {
        assert!(!matrix_rehash_override_enabled(true, false));
        assert!(matrix_rehash_override_enabled(true, true));
        assert!(!matrix_rehash_override_enabled(false, true));
    }

    #[test]
    fn selected_history_session_is_tier_bound_and_uses_typed_overlap() {
        let gate = ProofTopologyGate::for_tests();
        let session =
            begin_selected_history_proof_session_for_tests(&gate, SelectedRecursiveTier::B64)
                .expect("selected-small session admission");
        assert!(session.admits_tier(SelectedRecursiveTier::B8));
        assert!(session.admits_tier(SelectedRecursiveTier::B64));
        assert!(!session.admits_tier(SelectedRecursiveTier::B255));
        assert!(matches!(
            session.require_tier(SelectedRecursiveTier::B255),
            Err(SelectedRecursiveProverError::SessionTierMismatch {
                session: "B8-B64",
                requested: SelectedRecursiveTier::B255,
            })
        ));
        let native_b8 = gate
            .try_admit_native_user_txs(1)
            .expect("approved native B8 overlap")
            .expect("native proof reservation");
        assert!(matches!(
            gate.try_admit_recursive_tier(8),
            Err(ProofTopologyAdmissionError::Busy)
        ));
        assert!(matches!(
            gate.try_admit_recursive_link(),
            Err(ProofTopologyAdmissionError::Busy)
        ));
        drop(native_b8);

        drop(session);
        assert!(
            begin_selected_history_proof_session_for_tests(&gate, SelectedRecursiveTier::B255,)
                .is_ok()
        );

        let unwind_gate = gate.clone();
        let unwound = std::panic::catch_unwind(move || {
            let _session = begin_selected_history_proof_session_for_tests(
                &unwind_gate,
                SelectedRecursiveTier::B255,
            )
            .expect("session admission before synthetic panic");
            panic!("synthetic selected-history session panic");
        });
        assert!(unwound.is_err());
        assert!(
            begin_selected_history_proof_session_for_tests(&gate, SelectedRecursiveTier::B64,)
                .is_ok()
        );
    }

    #[test]
    fn pipeline_session_allows_exactly_one_block_and_one_link_lane() {
        let gate = ProofTopologyGate::for_tests();
        let session =
            begin_selected_history_proof_session_for_tests(&gate, SelectedRecursiveTier::B64)
                .expect("selected-history session admission");

        std::thread::scope(|scope| {
            let (block_started_tx, block_started_rx) = std::sync::mpsc::channel();
            let (release_block_tx, release_block_rx) = std::sync::mpsc::channel();
            let session = &session;
            scope.spawn(move || {
                let _block = session
                    .try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Block)
                    .expect("first Block lane");
                block_started_tx.send(()).expect("signal held Block lane");
                // A failed assertion in the parent drops the sender and wakes
                // this thread too, so this focused test cannot hang on failure.
                let _ = release_block_rx.recv();
            });

            block_started_rx.recv().expect("Block lane became active");
            assert!(matches!(
                session.try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Block),
                Err(SelectedRecursiveProverError::PipelineLaneBusy { requested: "Block" })
            ));
            assert!(matches!(
                session.try_acquire_pipeline_lane(SelectedHistoryPipelineLane::ExclusiveB255),
                Err(SelectedRecursiveProverError::PipelineLaneBusy {
                    requested: "B255 Block/Link"
                })
            ));
            let link = session
                .try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Link)
                .expect("one Link may overlap one non-B255 Block");
            assert!(matches!(
                session.try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Link),
                Err(SelectedRecursiveProverError::PipelineLaneBusy { requested: "Link" })
            ));
            drop(link);
            release_block_tx.send(()).expect("release held Block lane");
        });

        drop(
            session
                .try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Block)
                .expect("Block lane reopens after its owning permit drops"),
        );
    }

    #[test]
    fn b255_lane_is_exclusive_and_permit_releases_on_error_and_unwind() {
        let gate = ProofTopologyGate::for_tests();
        let session =
            begin_selected_history_proof_session_for_tests(&gate, SelectedRecursiveTier::B255)
                .expect("selected-history B255 session admission");

        assert_eq!(
            SelectedHistoryProofSession::pipeline_lane_for_tier(
                SelectedRecursiveTier::B255,
                SelectedHistoryPipelineLane::Block,
            ),
            SelectedHistoryPipelineLane::ExclusiveB255,
        );
        assert_eq!(
            SelectedHistoryProofSession::pipeline_lane_for_tier(
                SelectedRecursiveTier::B255,
                SelectedHistoryPipelineLane::Link,
            ),
            SelectedHistoryPipelineLane::ExclusiveB255,
        );
        assert_eq!(
            SelectedHistoryProofSession::pipeline_lane_for_tier(
                SelectedRecursiveTier::B64,
                SelectedHistoryPipelineLane::Link,
            ),
            SelectedHistoryPipelineLane::Link,
        );

        let exclusive = session
            .try_acquire_pipeline_lane(SelectedHistoryPipelineLane::ExclusiveB255)
            .expect("exclusive B255 Block/Link lane");
        for lane in [
            SelectedHistoryPipelineLane::Block,
            SelectedHistoryPipelineLane::Link,
            SelectedHistoryPipelineLane::ExclusiveB255,
        ] {
            assert!(matches!(
                session.try_acquire_pipeline_lane(lane),
                Err(SelectedRecursiveProverError::PipelineLaneBusy { .. })
            ));
        }
        drop(exclusive);

        let link = session
            .try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Link)
            .expect("ordinary Link lane");
        assert!(matches!(
            session.try_acquire_pipeline_lane(SelectedHistoryPipelineLane::ExclusiveB255),
            Err(SelectedRecursiveProverError::PipelineLaneBusy {
                requested: "B255 Block/Link"
            })
        ));
        drop(link);

        let failed = (|| {
            let _permit = session.try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Block)?;
            Err::<(), _>(SelectedRecursiveProverError::RecursiveAssemblyRejected)
        })();
        assert!(matches!(
            failed,
            Err(SelectedRecursiveProverError::RecursiveAssemblyRejected)
        ));
        drop(
            session
                .try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Block)
                .expect("error propagation releases the Block lane"),
        );

        let unwound = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _permit = session
                .try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Link)
                .expect("Link lane before synthetic panic");
            panic!("synthetic pipeline lane panic");
        }));
        assert!(unwound.is_err());
        drop(
            session
                .try_acquire_pipeline_lane(SelectedHistoryPipelineLane::Link)
                .expect("unwind releases the Link lane"),
        );
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
        // Split at the test module, not the first `#[cfg(test)]` item: the
        // file carries one test-gated session helper mid-file.
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
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
            .split("fn build_and_prove_selected_compact")
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

    fn resident_matrix(matrix: &LoadedSelectedRecursiveFoldMatrix) -> &FieldR1cs {
        match matrix {
            LoadedSelectedRecursiveFoldMatrix::Resident(matrix) => matrix.matrix(),
            LoadedSelectedRecursiveFoldMatrix::Compact(_) => {
                panic!("test source unexpectedly returned a compact matrix")
            }
        }
    }

    fn compact_matrix(matrix: FieldR1cs) -> Arc<CompactFieldR1cs> {
        let shape = FieldShape::of(&matrix);
        let digest = matrix.structural_statement_digest();
        let mut artifact = Vec::new();
        matrix
            .write_artifact(&mut artifact)
            .expect("tiny fixture serializes");
        Arc::new(
            CompactFieldR1cs::open(artifact.into_boxed_slice(), shape, digest)
                .expect("tiny fixture authenticates"),
        )
    }

    struct CompactOnlyMatrixSource {
        previous: Arc<CompactFieldR1cs>,
        block: Arc<CompactFieldR1cs>,
        compact_calls: Vec<SelectedRecursiveMatrixKind>,
        resident_calls: usize,
    }

    impl SelectedRecursiveMatrixSource for CompactOnlyMatrixSource {
        type Error = &'static str;

        fn load_compact_matrix(
            &mut self,
            request: SelectedRecursiveMatrixRequest,
        ) -> Result<Option<Arc<CompactFieldR1cs>>, Self::Error> {
            self.compact_calls.push(request.kind());
            let matrix = match request.kind() {
                SelectedRecursiveMatrixKind::GenesisLink
                | SelectedRecursiveMatrixKind::PreviousLink(_) => Arc::clone(&self.previous),
                SelectedRecursiveMatrixKind::CurrentBlock(_) => Arc::clone(&self.block),
            };
            Ok(Some(matrix))
        }

        fn load_matrix(
            &mut self,
            _request: SelectedRecursiveMatrixRequest,
        ) -> Result<LoadedSelectedRecursiveMatrix, Self::Error> {
            self.resident_calls += 1;
            Err("resident fallback must not run")
        }
    }

    #[test]
    fn sequential_link_driver_prefers_compact_source_without_csr_fallback() {
        let previous = tiny_matrix(51);
        let block = tiny_matrix(52);
        let previous_request = request(
            SelectedRecursiveMatrixKind::PreviousLink(SelectedRecursiveTier::B8),
            &previous,
        );
        let block_request = request(
            SelectedRecursiveMatrixKind::CurrentBlock(SelectedRecursiveTier::B8),
            &block,
        );
        let mut source = CompactOnlyMatrixSource {
            previous: compact_matrix(previous),
            block: compact_matrix(block),
            compact_calls: Vec::new(),
            resident_calls: 0,
        };

        let result = run_sequential_matrix_phases(
            &mut source,
            previous_request,
            block_request,
            (),
            |(), loaded| match loaded {
                LoadedSelectedRecursiveFoldMatrix::Compact(matrix)
                    if matrix.shape() == previous_request.shape()
                        && matrix.statement_digest() == previous_request.statement_digest() =>
                {
                    Ok::<_, &'static str>(7usize)
                }
                _ => Err("previous compact identity"),
            },
            |phase, loaded| match loaded {
                LoadedSelectedRecursiveFoldMatrix::Compact(matrix)
                    if phase == 7
                        && matrix.shape() == block_request.shape()
                        && matrix.statement_digest() == block_request.statement_digest() =>
                {
                    Ok::<_, &'static str>(8usize)
                }
                _ => Err("block compact identity"),
            },
        )
        .expect("compact phases complete");
        assert_eq!(result, 8);
        assert_eq!(source.resident_calls, 0);
        assert_eq!(
            source.compact_calls,
            vec![previous_request.kind(), block_request.kind()]
        );
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
            |(), loaded| {
                let matrix = resident_matrix(loaded);
                (FieldShape::of(matrix) == previous_request.shape()
                    && matrix.structural_statement_digest() == previous_request.statement_digest())
                .then_some(7usize)
                .ok_or("previous matrix identity")
            },
            |phase, loaded| {
                let matrix = resident_matrix(loaded);
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
            |(), loaded| {
                let matrix = resident_matrix(loaded);
                (matrix.structural_statement_digest() == genesis_request.statement_digest())
                    .then_some(())
                    .ok_or("genesis matrix identity")
            },
            |(), loaded| {
                let matrix = resident_matrix(loaded);
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
            |(), loaded| {
                let matrix = resident_matrix(loaded);
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
            .split("fn prove_selected_recursive_link_with_gate")
            .nth(1)
            .expect("standalone Link admission")
            .split("fn prove_selected_recursive_link_in_reserved_session")
            .next()
            .expect("standalone admission boundary");
        assert!(standalone.contains("try_admit_recursive_link"));
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
        assert!(coordinator.contains(".prepare_previous_link_compact(matrix)"));
        assert!(coordinator.contains(".prepare_previous_link(matrix.matrix())"));
        assert!(coordinator.contains(".prepare_previous_link_compact_locally_authored("));
        assert!(coordinator.contains(".prepare_previous_link_locally_authored("));
        assert!(coordinator.contains(".prepare_current_block_compact(matrix)"));
        assert!(coordinator.contains(".prepare_current_block(matrix.matrix())"));
        assert!(coordinator.contains(".prepare_current_block_compact_locally_authored("));
        assert!(coordinator.contains(".prepare_current_block_locally_authored("));
        assert!(coordinator.contains("prepared.assemble()"));
        assert!(coordinator.contains("prepared.assemble_witness_only_established(&relation)"));
        assert!(coordinator.contains("prove_built_split_link"));
        assert!(coordinator.contains("prove_built_split_link_compact"));
        assert!(coordinator.contains("prove_built_split_link_locally_authored"));
        assert!(coordinator.contains("prove_built_split_link_compact_locally_authored"));
        assert!(!coordinator.contains(".or_else("));
        assert!(!coordinator.contains("build_split_link("));
        assert!(!coordinator.contains("SplitLinkInput"));
    }

    #[test]
    fn pipelined_local_replay_is_mandatory_linear_and_not_a_full_verify_fallback() {
        let source = include_str!("recursive_prover.rs");

        for name in [
            "SelectedRecursiveBlockProof",
            "SelectedRecursiveLocalLinkReplay",
            "SelectedRecursiveLinkProof",
        ] {
            let declaration = format!("pub struct {name} {{");
            let declaration_at = source
                .find(&declaration)
                .expect("local replay carrier declaration");
            let attributes = source[..declaration_at]
                .rsplit("\n\n")
                .next()
                .expect("local replay carrier attributes");
            assert!(!attributes.contains("#[derive("), "{name} became derivable");
            assert!(!source.contains(&format!("impl Clone for {name}")));
            assert!(!source.contains(&format!("Serialize for {name}")));
            assert!(!source.contains(&format!("Deserialize for {name}")));
        }
        let local_link_fields = source
            .split("pub struct SelectedRecursiveLocalLinkReplay {")
            .nth(1)
            .expect("local Link replay declaration")
            .split('}')
            .next()
            .expect("local Link replay fields");
        assert!(!local_link_fields.lines().any(|line| {
            let line = line.trim_start();
            line.starts_with("pub ") || line.starts_with("pub(")
        }));
        for carrier in ["SelectedRecursiveBlockProof", "SelectedRecursiveLinkProof"] {
            let declaration = format!("pub struct {carrier} {{");
            let fields = source
                .split(declaration.as_str())
                .nth(1)
                .expect("proof carrier declaration")
                .split('}')
                .next()
                .expect("proof carrier fields");
            let replay_field = fields
                .lines()
                .find(|line| line.contains("locally_authored_replay:"))
                .expect("private replay field");
            assert!(!replay_field.trim_start().starts_with("pub"));
        }

        let session_impl = source
            .split("impl SelectedHistoryProofSession")
            .nth(1)
            .expect("selected-history session impl")
            .split("pub fn begin_selected_history_proof_session")
            .next()
            .expect("session impl boundary");
        let standalone_block = session_impl
            .split("pub fn prove_block(")
            .nth(1)
            .expect("standalone Block method")
            .split("pub fn prove_block_with_matrices")
            .next()
            .expect("standalone Block boundary");
        assert!(standalone_block
            .contains("prove_selected_recursive_block_in_reserved_session(classes, job)"));
        assert!(!standalone_block.contains("locally_authored"));
        let standalone_link = session_impl
            .split("pub fn prove_link<")
            .nth(1)
            .expect("standalone Link method")
            .split("pub fn prove_block_pipelined")
            .next()
            .expect("standalone Link boundary");
        assert!(standalone_link.contains(
            "prove_selected_recursive_link_in_reserved_session(classes, job, matrices, false)"
        ));
        assert!(!standalone_link.contains("locally_authored"));
        let pipelined_link = session_impl
            .split("pub fn prove_link_pipelined")
            .nth(1)
            .expect("pipelined Link method");
        assert!(pipelined_link.contains("locally_authored_replay.is_none()"));
        assert!(pipelined_link.contains("LocalReplayRequired"));
        assert!(pipelined_link.contains(", true)"));

        let binding = source
            .split("pub fn bind_decoded_predecessor")
            .nth(1)
            .expect("local predecessor binding")
            .split("const PIPELINE_BLOCK_LANE")
            .next()
            .expect("binding boundary");
        assert!(binding.contains("PreviousLocallyAuthored"));
        assert!(binding.contains("LocalReplayTierMismatch"));
        assert!(!binding.contains("clone()"));
        assert!(!binding.contains("verify_"));

        let coordinator = source
            .split("fn prove_selected_recursive_link_in_reserved_session")
            .nth(1)
            .expect("reserved production Link coordinator")
            .split("fn map_sequential_link_error")
            .next()
            .expect("coordinator boundary");
        assert!(coordinator.contains("previous_auth_mode"));
        assert!(coordinator.contains("block_auth_mode"));
        assert!(coordinator
            .contains("!capture_locally_authored_link && current_block_replay.is_some()"));
        assert!(!coordinator.contains(".or_else("));
    }

    #[test]
    fn reserved_session_paths_never_reenter_topology_gate() {
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
