// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Crash-resumable production worker for selected Block+Link history proofs.
//!
//! This module is deliberately synchronous: the prover-role node calls
//! [`SelectedHistoryProverWorker::run_pipelined`] from its bounded blocking
//! worker.  Ordinary validating nodes never construct this worker.  One
//! invocation acquires one proof-topology session and then pipelines a bounded
//! window of consecutive durable MDBX jobs through three stages:
//!
//! - stage A (controller thread): claim -> load inputs -> native replay ->
//!   selected Block proof.  Height `N+1` starts after stage A of `N` has
//!   produced its in-memory end-state cursor and Block proof; it never waits
//!   for `N`'s Link, verification, or promotion.
//! - stage B (link lane): the selected Link proof.  It chains on the terminal
//!   package of `N-1`, taken from this lane's own previous output (or from
//!   the durable predecessor result at the pipeline head), so Link proving is
//!   sequential by nature but overlaps the other stages.
//! - stage C (verify lane): terminal package stream-verification followed by
//!   the atomic promote.  Promotes run strictly in height order and the
//!   store's exact-predecessor coverage check remains the final authority.
//!
//! The durable artifacts are byte-identical to the sequential worker's: the
//! terminal package persisted at promote `N` is exactly what stage B produced
//! and stage C verified, while the same transaction persists the ladder
//! cursor update that in-flight `N+1` already consumed.
//! On any failure, cancellation, reorg, or restart the pipeline collapses to
//! the durable state and re-claims (jobs are durable and idempotent; the
//! `RunningJobGuard` pattern releases every unpromoted claim).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use noid_block::{reconstruct_selected_recursive_block_artifacts, FullAcceptedBlockBatchItem};
use noid_chain::block::Block;
use noid_chain::consensus::header::asert_anchor_height;
use noid_chain::consensus::params::{EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS, TX_EPOCH_BLOCKS};
use noid_chain::storage::{
    derive_touched_segment_ids, load_selected_history_ladder_parent_state,
    load_selected_history_pipelined_parent_state, MdbxStore, RecursiveProofJob,
    RecursiveProofJobState, RecursiveProofJobTier,
};
use noid_chain::{block_id, BlockHeader, SelectedHistoryLadderUpdate};
use noid_miner::recursive_prover::SelectedRecursiveLocalLinkReplay;
use noid_miner::{
    begin_selected_history_proof_session, selected_recursive_tier,
    LoadedSelectedRecursiveClassRegistry, PinnedSelectedRecursiveClassRegistrySource,
    SelectedHistoryProofSession, SelectedRecursiveBlockClasses, SelectedRecursiveBlockJob,
    SelectedRecursiveBlockProof, SelectedRecursiveLinkClasses, SelectedRecursiveLinkJob,
    SelectedRecursiveLinkPredecessor, SelectedRecursiveMatrixArtifactIdentity,
    SelectedRecursiveMatrixSource, SelectedRecursiveProverError, SelectedRecursiveTier,
};
use noid_recursive::acceptance::split_link::tip_block_accumulator_split;
use noid_recursive::{
    decode_selected_history_terminal_package, genesis_accumulator, ChainAccumulator,
    RecursiveConsensusState, SelectedHistoryMatrixSource, SelectedHistoryTerminalPackage,
};

/// Small identity copied out of a durable claim for logging/backoff only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedHistoryJobIdentity {
    pub height: u64,
    pub block_hash: [u8; 32],
}

impl From<RecursiveProofJob> for SelectedHistoryJobIdentity {
    fn from(job: RecursiveProofJob) -> Self {
        Self {
            height: job.height,
            block_hash: job.block_hash,
        }
    }
}

/// Why the caller should stop this polling iteration and apply backoff.
#[derive(Debug, PartialEq, Eq)]
pub enum SelectedHistoryWorkerBackoff {
    /// The durable queue currently has no canonical pending entry.
    Idle,
    /// The prover role is shutting down or has been administratively paused.
    Cancelled,
    /// Another incompatible process-local proof stage currently owns the
    /// topology slot needed to start this drain.
    ProofStageBusy,
    /// A bounded local input/artifact/cryptographic phase failed closed.
    RetryableFailure { phase: &'static str, detail: String },
    /// A proof backend assertion unwound through the production boundary.
    Panicked,
}

/// Result of exactly one non-queueing worker poll.
///
/// A pipelined poll may promote several consecutive heights before it stops;
/// each promotion is logged with its per-stage timings as it happens, and
/// `Completed` reports the highest one.  `Backoff` carries the first failure
/// that collapsed the pipeline; all downstream in-flight claims were already
/// released back to Pending.
#[derive(Debug, PartialEq, Eq)]
pub enum SelectedHistoryWorkerOutcome {
    Completed(SelectedHistoryJobIdentity),
    Backoff {
        job: Option<SelectedHistoryJobIdentity>,
        reason: SelectedHistoryWorkerBackoff,
        /// A stale/reorged claim may no longer be releasable.  The original
        /// reason remains primary and this bounded diagnostic records that
        /// the durable release transaction also failed.
        release_error: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Explicit pipeline depth policy
// ---------------------------------------------------------------------------

/// Scheduler parameters, not consensus constants.  Depth is the number of
/// consecutive heights allowed in flight at once (claimed and unpromoted).
/// Depth 1 is exactly the historical sequential worker.  Depth 2 overlaps the
/// next height's replay+Block-prove (and then its Link) with the current
/// height's Link/verify/promote; depth 3 additionally lets a third height
/// enter stage A while the two older ones occupy the Link and verify lanes.
/// Every stage still runs one-at-a-time in its own lane. The bounded channels
/// own the concurrency limit directly: B8-B64 keep Block, Link and Verify
/// occupied; B255 remains sequential until its overlap HWM is measured.
const PIPELINE_STANDARD_DEPTH: usize = 3;

/// Bounded stage handoff and controller polling granularity.
const PIPELINE_STAGE_CHANNEL_CAPACITY: usize = 1;
const PIPELINE_WAIT_TICK: Duration = Duration::from_millis(100);
/// How often the controller re-polls the durable queue while the lanes are
/// still busy and no pending job is claimable.  Bounds claim-transaction
/// churn against the block-import writer.
const PIPELINE_IDLE_CLAIM_INTERVAL: Duration = Duration::from_secs(1);

/// Conservative, explicit depth decision for the next claim.
///
/// B255 witnesses are the worst case for in-flight memory, so any B255 job —
/// the next one or one already in flight — collapses the window to strictly
/// sequential processing. Other tiers follow the topology, not host-memory
/// polling or estimated byte thresholds.
fn planned_pipeline_depth(
    next_tier: RecursiveProofJobTier,
    in_flight_tiers: &[RecursiveProofJobTier],
) -> usize {
    if next_tier == RecursiveProofJobTier::B255
        || in_flight_tiers.contains(&RecursiveProofJobTier::B255)
    {
        return 1;
    }
    PIPELINE_STANDARD_DEPTH
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// Prover-role owner of one immutable decoded registry and three lightweight
/// handles over the shared authenticated compact matrix bank (one per
/// overlapped matrix-using lane). It owns no proof queue, relation matrix, or
/// chain state; only one bounded process-local replay tail may survive a
/// deliberate proof-session yield.
pub struct SelectedHistoryProverWorker<Registry, BlockMatrices, LinkMatrices, VerifyMatrices> {
    store: MdbxStore,
    registry_store: Registry,
    expected_registry_digest: [u8; 32],
    /// One pinned, fully materialized immutable prover registry for the
    /// worker's lifetime. Production measurement on the canonical four-tier
    /// release is ~69 MiB retained (the 368 MiB governor figure is a
    /// conservative transient materialization envelope). Keeping this value
    /// removes 6-8 seconds of repeated VK reconstruction from every
    /// one-height steady-state drain.
    loaded_registry: Option<LoadedSelectedRecursiveClassRegistry>,
    /// Used by the replay/Block lane (stage A). Embedded production handles
    /// share one authenticated compact bank, so this adds only an `Arc` and
    /// never duplicates the frozen Block relation.
    block_matrix_source: BlockMatrices,
    /// Used by the Link lane (stage B).  Shares the process-wide one-matrix
    /// residency with the verify source, so at most one transient matrix is
    /// decoded at any time even while the lanes overlap.
    link_matrix_source: LinkMatrices,
    /// Used by the terminal-verify lane (stage C).
    verify_matrix_source: VerifyMatrices,
    /// Retained across drains so `cadence_ms` remains meaningful when the
    /// worker catches up and later processes one freshly mined height per
    /// polling iteration.
    last_promoted_at: Option<Instant>,
    /// Process-local replay authority for the last package this worker both
    /// authored and promoted. It may cross the intentional three-height
    /// proof-session yield, but never a restart, reorg, remote coverage
    /// advance, byte mismatch, or cancellation.
    local_replay_tail: Option<InPipelinePackage<SelectedRecursiveLocalLinkReplay>>,
}

impl<Registry, BlockMatrices, LinkMatrices, VerifyMatrices>
    SelectedHistoryProverWorker<Registry, BlockMatrices, LinkMatrices, VerifyMatrices>
where
    Registry: PinnedSelectedRecursiveClassRegistrySource,
    BlockMatrices: SelectedRecursiveMatrixSource + Send,
    LinkMatrices: SelectedRecursiveMatrixSource + Send,
    VerifyMatrices: SelectedHistoryMatrixSource + Send,
{
    pub fn new(
        store: MdbxStore,
        registry_store: Registry,
        expected_registry_digest: [u8; 32],
        block_matrix_source: BlockMatrices,
        link_matrix_source: LinkMatrices,
        verify_matrix_source: VerifyMatrices,
    ) -> Self {
        Self {
            store,
            registry_store,
            expected_registry_digest,
            loaded_registry: None,
            block_matrix_source,
            link_matrix_source,
            verify_matrix_source,
            last_promoted_at: None,
            local_replay_tail: None,
        }
    }

    /// Authenticate and materialize the immutable prover registry once.
    ///
    /// Startup code may call this while it owns proof admission, before any
    /// miner task can start. `run_pipelined` retains the same fail-closed lazy
    /// path for tests and non-daemon callers which do not explicitly prewarm.
    pub fn preload_registry(&mut self) -> Result<(), Registry::Error> {
        let _ = populate_registry_cache(
            &self.registry_store,
            self.expected_registry_digest,
            &mut self.loaded_registry,
        )?;
        Ok(())
    }

    /// Return all embedded matrix pins from the already-authenticated full
    /// registry without reading or materializing the registry a second time.
    ///
    /// Startup calls this immediately after [`Self::preload_registry`] to
    /// prewarm the compact matrix bank before mining begins. A missing preload
    /// is an explicit error rather than an implicit registry load so proof
    /// admission and startup ordering remain visible to the caller.
    pub fn preloaded_registry_artifact_identities(
        &self,
    ) -> Result<[SelectedRecursiveMatrixArtifactIdentity; 9], SelectedRecursiveProverError> {
        let registry = self
            .loaded_registry
            .as_ref()
            .ok_or(SelectedRecursiveProverError::RegistryNotPreloaded)?;
        Ok(registry.link_classes()?.canonical_artifact_identities())
    }

    /// Claim and process a bounded pipeline of consecutive selected recursive
    /// proof jobs inside one proof-topology session.
    ///
    /// The pipeline reads parent state exclusively from its durable forward
    /// ladder cursor plus the bounded in-memory updates of lower in-flight
    /// heights. It never borrows the node's canonical-tip `ChainState` and
    /// therefore holds no chain lock while proving.
    pub fn run_pipelined(&mut self, cancelled: &AtomicBool) -> SelectedHistoryWorkerOutcome {
        let Self {
            store,
            registry_store,
            expected_registry_digest,
            loaded_registry,
            block_matrix_source,
            link_matrix_source,
            verify_matrix_source,
            last_promoted_at,
            local_replay_tail,
        } = self;
        let store: &MdbxStore = store;
        if cancelled.load(Ordering::Acquire) {
            drop(local_replay_tail.take());
        }

        // Exactly one durable claim precedes admission, exactly as the
        // sequential worker did: an idle or memory-pressured poll neither
        // holds the session nor materializes the registry.
        let (head, head_identity, proof_session) =
            match prepare_pipeline_head_with_admission(store, cancelled, |tier| {
                begin_selected_history_proof_session(selected_tier_from_storage(tier))
                    .map_err(map_prover_admission)
            }) {
                Ok(prepared) => prepared,
                Err(outcome) => {
                    if cancelled.load(Ordering::Acquire) {
                        drop(local_replay_tail.take());
                    }
                    return outcome;
                }
            };
        let mut head = head;

        // The daemon startup path already preloaded this registry under its
        // exclusive prewarm profile. The lazy compatibility path remains
        // inside the head tier's owning proof-session admission.
        let registry_load_started = Instant::now();
        let registry_cache_hit = match populate_registry_cache(
            registry_store,
            *expected_registry_digest,
            loaded_registry,
        ) {
            Ok(cache_hit) => cache_hit,
            Err(error) => {
                return release_backoff(
                    &mut head,
                    head_identity,
                    retryable("load pinned selected-history registry", error),
                );
            }
        };
        let registry_load_ms = elapsed_ms(registry_load_started);
        tracing::info!(
            registry_cache_hit,
            registry_load_ms,
            "selected-history prover registry ready"
        );
        let loaded_registry = loaded_registry
            .as_ref()
            .expect("selected-history registry cache populated above");
        let block_classes = match loaded_registry.block_classes() {
            Ok(classes) => classes,
            Err(error) => {
                return release_backoff(
                    &mut head,
                    head_identity,
                    retryable("validate Block class registry", error),
                );
            }
        };
        let link_classes = match loaded_registry.link_classes() {
            Ok(classes) => classes,
            Err(error) => {
                return release_backoff(
                    &mut head,
                    head_identity,
                    retryable("validate Link class registry", error),
                );
            }
        };
        if cancelled.load(Ordering::Acquire) {
            drop(local_replay_tail.take());
            return release_backoff(
                &mut head,
                head_identity,
                SelectedHistoryWorkerBackoff::Cancelled,
            );
        }

        let registry = loaded_registry;
        let block_classes = &block_classes;
        let link_classes = &link_classes;
        let session = &proof_session;
        let mut cross_session_tail =
            take_cross_session_local_replay_tail(head.job, local_replay_tail.take());
        let mut cross_session_expectation =
            cross_session_tail
                .as_ref()
                .map(|tail| CrossSessionTailExpectation {
                    height: tail.height,
                    block_hash: tail.block_hash,
                    encoded: Arc::clone(&tail.encoded),
                });
        let summary = run_selected_history_pipeline(
            store,
            cancelled,
            head,
            last_promoted_at,
            planned_pipeline_depth,
            |job, handoffs| {
                // Only the first Stage-A snapshot can authorize the retained
                // predecessor capability. Later heights use the Link lane's
                // own in-session output, even when depth=1 has already
                // retired the preceding handoff.
                let expected_cross_session_tail = cross_session_expectation.take();
                stage_replay_and_prove_block(
                    store,
                    registry,
                    block_classes,
                    link_classes,
                    session,
                    block_matrix_source,
                    cancelled,
                    job,
                    handoffs,
                    expected_cross_session_tail.as_ref(),
                )
            },
            move |job, in_pipeline, staged| {
                // The lane itself supplies in-session predecessors. Only its
                // first invocation can consume the worker's retained tail,
                // and only after Stage A authenticated its exact bytes and
                // coverage in the same MDBX snapshot that loaded the job.
                let session_tail =
                    if in_pipeline.is_none() && staged.cross_session_tail_matches_durable {
                        cross_session_tail.take()
                    } else {
                        None
                    };
                let in_pipeline = in_pipeline.or(session_tail);
                stage_link_and_package(
                    registry,
                    link_classes,
                    session,
                    link_matrix_source,
                    cancelled,
                    job,
                    in_pipeline,
                    staged,
                )
            },
            |job, staged| {
                stage_verify_terminal(
                    store,
                    registry,
                    verify_matrix_source,
                    cancelled,
                    job,
                    staged,
                )
            },
        );
        let PipelineRunSummary {
            last_promoted,
            stop,
            tail_package,
            ..
        } = summary;
        *local_replay_tail =
            retain_cross_session_local_replay_tail(stop.as_ref(), last_promoted, tail_package);
        match stop {
            None => match last_promoted {
                Some(identity) => SelectedHistoryWorkerOutcome::Completed(identity),
                None => backoff(None, SelectedHistoryWorkerBackoff::Idle, None),
            },
            Some(PipelineStopRecord::Superseded { identity }) => {
                backoff(Some(identity), SelectedHistoryWorkerBackoff::Idle, None)
            }
            Some(PipelineStopRecord::Cancelled {
                identity,
                release_error,
            }) => backoff(
                identity,
                SelectedHistoryWorkerBackoff::Cancelled,
                release_error,
            ),
            Some(PipelineStopRecord::Failed {
                identity,
                reason,
                release_error,
            }) => backoff(identity, reason, release_error),
        }
    }
}

/// Populate the worker-owned immutable registry once. Returning whether this
/// was a cache hit makes the production timing explicit and keeps both the
/// eager startup path and lazy non-daemon path on one authenticated loader.
fn populate_registry_cache<Registry: PinnedSelectedRecursiveClassRegistrySource>(
    registry_store: &Registry,
    expected_registry_digest: [u8; 32],
    loaded_registry: &mut Option<LoadedSelectedRecursiveClassRegistry>,
) -> Result<bool, Registry::Error> {
    if loaded_registry.is_some() {
        return Ok(true);
    }
    *loaded_registry = Some(registry_store.load_pinned_registry(expected_registry_digest)?);
    Ok(false)
}

/// Claim the numerically-lowest canonical pending job strictly above valid
/// selected-history coverage.  This is the sole durable-claim callsite; the
/// pipeline controller re-invokes it for every additional in-flight height.
fn claim_next_pipeline_job<'a>(
    store: &'a MdbxStore,
) -> Result<Option<RunningJobGuard<'a>>, SelectedHistoryWorkerBackoff> {
    match store.claim_next_recursive_proof_job() {
        Ok(Some(job)) => Ok(Some(RunningJobGuard::new(store, job))),
        Ok(None) => Ok(None),
        Err(error) => Err(retryable("claim durable job", error)),
    }
}

/// Claim the pipeline head and reserve the complete m24 envelope before any
/// chain metadata or registry table is materialized.  Admission failure
/// therefore adds no allocation to an already memory-pressured process.
fn prepare_pipeline_head_with_admission<'a, A, S>(
    store: &'a MdbxStore,
    cancelled: &AtomicBool,
    admission: A,
) -> Result<(RunningJobGuard<'a>, SelectedHistoryJobIdentity, S), SelectedHistoryWorkerOutcome>
where
    A: FnOnce(RecursiveProofJobTier) -> Result<S, SelectedHistoryWorkerBackoff>,
{
    if cancelled.load(Ordering::Acquire) {
        return Err(backoff(None, SelectedHistoryWorkerBackoff::Cancelled, None));
    }

    let mut running = match claim_next_pipeline_job(store) {
        Ok(Some(running)) => running,
        Ok(None) => return Err(backoff(None, SelectedHistoryWorkerBackoff::Idle, None)),
        Err(reason) => return Err(backoff(None, reason, None)),
    };
    let identity = SelectedHistoryJobIdentity::from(running.job);

    if cancelled.load(Ordering::Acquire) {
        return Err(release_backoff(
            &mut running,
            identity,
            SelectedHistoryWorkerBackoff::Cancelled,
        ));
    }

    let session = match catch_unwind(AssertUnwindSafe(|| admission(running.job.tier))) {
        Ok(Ok(session)) => session,
        Ok(Err(reason)) => return Err(release_backoff(&mut running, identity, reason)),
        Err(_) => {
            return Err(release_backoff(
                &mut running,
                identity,
                SelectedHistoryWorkerBackoff::Panicked,
            ));
        }
    };
    if cancelled.load(Ordering::Acquire) {
        return Err(release_backoff(
            &mut running,
            identity,
            SelectedHistoryWorkerBackoff::Cancelled,
        ));
    }

    Ok((running, identity, session))
}

// ---------------------------------------------------------------------------
// Pipeline engine
// ---------------------------------------------------------------------------

/// End-of-replay cursor of one in-flight height: exactly the accumulator its
/// native replay produced and its streaming verification must reproduce.
/// The next height's stage A starts from this without waiting for the
/// producer's Link, verification, or promotion.
struct PipelineHandoff {
    height: u64,
    block_hash: [u8; 32],
    tier: RecursiveProofJobTier,
    end_accumulator: ChainAccumulator,
    ladder_update: Arc<SelectedHistoryLadderUpdate>,
}

/// Encoded terminal package of the immediately preceding in-flight height,
/// byte-identical to what its promote will persist.  The Link lane keeps the
/// most recent one so height `N+1` chains on `N` before `N` is durable.
struct InPipelinePackage<TL> {
    height: u64,
    block_hash: [u8; 32],
    encoded: Arc<Vec<u8>>,
    /// Opaque, non-durable authority minted beside this exact local Link.
    /// The next Link stage consumes it once; decoded network or MDBX packages
    /// can never manufacture this value.
    local_replay: TL,
}

/// Cheap, non-owning-bytes view passed from a retained process-local tail to
/// the first Stage-A snapshot of the next proof session. Cloning the `Arc`
/// copies no terminal-package bytes.
struct CrossSessionTailExpectation {
    height: u64,
    block_hash: [u8; 32],
    encoded: Arc<Vec<u8>>,
}

struct BlockStageResult<TB> {
    payload: TB,
    end_accumulator: ChainAccumulator,
    ladder_update: Arc<SelectedHistoryLadderUpdate>,
}

struct LinkStageResult<TV, TL> {
    payload: TV,
    encoded_package: Arc<Vec<u8>>,
    local_replay: TL,
}

struct LinkLaneUnit<'a, TB> {
    running: RunningJobGuard<'a>,
    identity: SelectedHistoryJobIdentity,
    payload: TB,
    claimed_at: Instant,
    block_ready_at: Instant,
    block_queue_ms: u64,
    block_ms: u64,
    ladder_update: Arc<SelectedHistoryLadderUpdate>,
}

struct VerifyLaneUnit<'a, TV> {
    running: RunningJobGuard<'a>,
    identity: SelectedHistoryJobIdentity,
    payload: TV,
    encoded_package: Arc<Vec<u8>>,
    claimed_at: Instant,
    verify_ready_at: Instant,
    block_queue_ms: u64,
    block_ms: u64,
    link_queue_ms: u64,
    link_ms: u64,
    ladder_update: Arc<SelectedHistoryLadderUpdate>,
}

struct PipelineCompletion {
    identity: SelectedHistoryJobIdentity,
}

/// First stop condition observed anywhere in the pipeline; later ones only
/// release their claims silently.
#[derive(Debug)]
enum PipelineStopRecord {
    Cancelled {
        identity: Option<SelectedHistoryJobIdentity>,
        release_error: Option<String>,
    },
    /// A promote was refused because coverage already advanced past the job
    /// (e.g. a verified terminal import).  Downstream in-flight work is
    /// discarded silently and the next poll re-claims from coverage.
    Superseded {
        identity: SelectedHistoryJobIdentity,
    },
    Failed {
        identity: Option<SelectedHistoryJobIdentity>,
        reason: SelectedHistoryWorkerBackoff,
        release_error: Option<String>,
    },
}

struct PipelineRunSummary<TL> {
    promoted: usize,
    last_promoted: Option<SelectedHistoryJobIdentity>,
    stop: Option<PipelineStopRecord>,
    tail_package: Option<InPipelinePackage<TL>>,
}

/// Admit only a height-consecutive retained tail as a Stage-A authorization
/// candidate. Canonical parent identity, exact coverage and exact durable
/// bytes are checked later inside the head's one atomic MDBX input snapshot;
/// a mismatch drops the candidate and uses that snapshot's durable result.
fn take_cross_session_local_replay_tail<TL>(
    head: RecursiveProofJob,
    tail: Option<InPipelinePackage<TL>>,
) -> Option<InPipelinePackage<TL>> {
    let tail = tail?;
    (tail.height.checked_add(1) == Some(head.height)).then_some(tail)
}

/// Retain only a package that completed full Stage-C verification and the
/// ordered promotion transaction in this successful drain. That transaction
/// is the authority here; the next claimed successor performs the sole exact
/// durable byte/coverage check before consuming the retained capability.
fn retain_cross_session_local_replay_tail<TL>(
    stop: Option<&PipelineStopRecord>,
    last_promoted: Option<SelectedHistoryJobIdentity>,
    tail: Option<InPipelinePackage<TL>>,
) -> Option<InPipelinePackage<TL>> {
    if stop.is_some() {
        return None;
    }
    let identity = last_promoted?;
    let tail = tail?;
    let identity_matches = identity.height == tail.height && identity.block_hash == tail.block_hash;
    identity_matches.then_some(tail)
}

struct PipelineControl {
    stop: Mutex<Option<PipelineStopRecord>>,
    stop_flag: AtomicBool,
    discard_floor: AtomicU64,
}

impl PipelineControl {
    fn new() -> Self {
        Self {
            stop: Mutex::new(None),
            stop_flag: AtomicBool::new(false),
            discard_floor: AtomicU64::new(u64::MAX),
        }
    }

    fn stopping(&self) -> bool {
        self.stop_flag.load(Ordering::Acquire)
    }

    fn record(&self, record: PipelineStopRecord) {
        let record_floor = stop_discard_floor(&record);
        self.discard_floor.fetch_min(record_floor, Ordering::AcqRel);
        let mut slot = self.stop.lock().expect("pipeline stop slot poisoned");
        // Keep the reason attached to the earliest invalid height. A later
        // lane can observe a higher-height failure first. Compare against the
        // reason protected by this same mutex, not the value returned by the
        // atomic `fetch_min`: two recorders may update the atomic before either
        // acquires the mutex, and the later lock holder must not overwrite a
        // lower-height reason with a stale pre-lock observation. Cancellation
        // remains terminal and keeps the first cancellation diagnostic.
        let replace = match slot.as_ref() {
            None => true,
            Some(existing) if matches!(existing, PipelineStopRecord::Cancelled { .. }) => false,
            Some(_) if matches!(&record, PipelineStopRecord::Cancelled { .. }) => true,
            Some(existing) => record_floor < stop_discard_floor(existing),
        };
        if replace {
            *slot = Some(record);
        }
        self.stop_flag.store(true, Ordering::Release);
    }

    /// Heights at or above this floor are invalidated by the recorded stop
    /// and must be discarded; units strictly below finish normally — their
    /// stages already succeeded and their ordered promotes depend only on
    /// their own predecessors, so a downstream failure never taints them.
    fn discard_floor(&self) -> Option<u64> {
        let floor = self.discard_floor.load(Ordering::Acquire);
        (floor != u64::MAX).then_some(floor)
    }

    fn discards(&self, height: u64) -> bool {
        self.discard_floor().is_some_and(|floor| height >= floor)
    }

    fn into_record(self) -> Option<PipelineStopRecord> {
        self.stop.into_inner().expect("pipeline stop slot poisoned")
    }
}

fn stop_discard_floor(record: &PipelineStopRecord) -> u64 {
    match record {
        // Shutdown wants the fast path: queued units are released, the
        // durable queue re-serves them after restart.
        PipelineStopRecord::Cancelled { .. } => 0,
        PipelineStopRecord::Superseded { identity } => identity.height,
        PipelineStopRecord::Failed {
            identity: Some(identity),
            ..
        } => identity.height,
        // A claim-side failure has no height and invalidates nothing already
        // in flight; a later lower stage failure is allowed to replace it.
        PipelineStopRecord::Failed { identity: None, .. } => u64::MAX,
    }
}

/// Release a failing unit's claim and record the first stop reason.
fn record_stage_failure(
    control: &PipelineControl,
    running: &mut RunningJobGuard<'_>,
    identity: SelectedHistoryJobIdentity,
    reason: SelectedHistoryWorkerBackoff,
) {
    let release_error = running.release().err();
    let record = if reason == SelectedHistoryWorkerBackoff::Cancelled {
        PipelineStopRecord::Cancelled {
            identity: Some(identity),
            release_error,
        }
    } else {
        PipelineStopRecord::Failed {
            identity: Some(identity),
            reason,
            release_error,
        }
    };
    control.record(record);
}

/// Drive a bounded window of consecutive heights through the three stages.
///
/// The controller (calling thread) runs stage A and owns claiming and the
/// explicit depth policy; two scoped lanes run stages B and C.  All stage
/// handoffs use bounded channels; every claim travels inside its unit as a
/// [`RunningJobGuard`], so any dropped unit — failure, cancellation, or
/// shutdown drain — releases its durable job back to Pending.  Only the
/// verify lane promotes, strictly in claim order.
fn run_selected_history_pipeline<'a, TB, TV, TL, DP, SB, SL, SV>(
    store: &'a MdbxStore,
    cancelled: &AtomicBool,
    head: RunningJobGuard<'a>,
    previous_promoted_at: &mut Option<Instant>,
    depth_policy: DP,
    mut stage_block: SB,
    stage_link: SL,
    stage_verify: SV,
) -> PipelineRunSummary<TL>
where
    TB: Send,
    TV: Send,
    TL: Send,
    DP: Fn(RecursiveProofJobTier, &[RecursiveProofJobTier]) -> usize,
    SB: FnMut(
        &RecursiveProofJob,
        &[PipelineHandoff],
    ) -> Result<BlockStageResult<TB>, SelectedHistoryWorkerBackoff>,
    SL: FnMut(
            &RecursiveProofJob,
            Option<InPipelinePackage<TL>>,
            TB,
        ) -> Result<LinkStageResult<TV, TL>, SelectedHistoryWorkerBackoff>
        + Send,
    SV: FnMut(&RecursiveProofJob, &TV) -> Result<(), SelectedHistoryWorkerBackoff> + Send,
{
    let session_head_tier = head.job.tier;
    let control = PipelineControl::new();
    let (link_tx, link_rx) =
        mpsc::sync_channel::<LinkLaneUnit<'a, TB>>(PIPELINE_STAGE_CHANNEL_CAPACITY);
    let (verify_tx, verify_rx) =
        mpsc::sync_channel::<VerifyLaneUnit<'a, TV>>(PIPELINE_STAGE_CHANNEL_CAPACITY);
    let (done_tx, done_rx) = mpsc::channel::<PipelineCompletion>();

    let mut promoted = 0usize;
    let mut last_promoted = None;

    let tail_package = std::thread::scope(|scope| {
        let control = &control;
        let link_handle = scope.spawn({
            let mut stage_link = stage_link;
            move || link_lane(control, cancelled, link_rx, verify_tx, &mut stage_link)
        });
        scope.spawn({
            let mut stage_verify = stage_verify;
            move || {
                verify_lane(
                    store,
                    control,
                    cancelled,
                    verify_rx,
                    done_tx,
                    previous_promoted_at,
                    &mut stage_verify,
                );
            }
        });

        // ------------------------- controller / stage A -------------------
        let mut pending_claim = Some(head);
        let mut in_flight: Vec<PipelineHandoff> = Vec::new();
        let mut drain_tail: Option<SelectedHistoryJobIdentity> = None;
        let link_tx = link_tx;

        let apply_completion =
            |completion: PipelineCompletion,
             in_flight: &mut Vec<PipelineHandoff>,
             promoted: &mut usize,
             last_promoted: &mut Option<SelectedHistoryJobIdentity>| {
                let fifo = in_flight.first().is_some_and(|handoff| {
                    handoff.height == completion.identity.height
                        && handoff.block_hash == completion.identity.block_hash
                });
                if !fifo {
                    control.record(PipelineStopRecord::Failed {
                        identity: Some(completion.identity),
                        reason: retryable_message(
                            "retire promoted pipeline prefix",
                            "verify lane reported an out-of-order completion",
                        ),
                        release_error: None,
                    });
                    return;
                }
                in_flight.remove(0);
                *promoted += 1;
                *last_promoted = Some(completion.identity);
            };

        'controller: loop {
            while let Ok(completion) = done_rx.try_recv() {
                apply_completion(
                    completion,
                    &mut in_flight,
                    &mut promoted,
                    &mut last_promoted,
                );
            }
            if control.stopping() {
                break;
            }
            if cancelled.load(Ordering::Acquire) {
                let record = match pending_claim.take() {
                    Some(mut running) => PipelineStopRecord::Cancelled {
                        identity: Some(SelectedHistoryJobIdentity::from(running.job)),
                        release_error: running.release().err(),
                    },
                    None => PipelineStopRecord::Cancelled {
                        identity: None,
                        release_error: None,
                    },
                };
                control.record(record);
                break;
            }

            if pending_claim.is_none() {
                let Some(tail) = drain_tail else {
                    break;
                };
                let Some(expected_height) = tail.height.checked_add(1) else {
                    control.record(PipelineStopRecord::Failed {
                        identity: None,
                        reason: retryable_message("claim durable job", "pipeline height overflow"),
                        release_error: None,
                    });
                    break;
                };

                // Peek at the exact successor before claiming it. This keeps
                // the depth bound honest (a claim itself counts as in flight)
                // and prevents a gap or fork-replaced parent from ever joining
                // the current drain.
                let next = match store.get_recursive_proof_job(expected_height) {
                    Ok(Some(next)) if next.state == RecursiveProofJobState::Pending => next,
                    Ok(_) => {
                        if in_flight.is_empty() {
                            break;
                        }
                        match done_rx.recv_timeout(PIPELINE_IDLE_CLAIM_INTERVAL) {
                            Ok(completion) => apply_completion(
                                completion,
                                &mut in_flight,
                                &mut promoted,
                                &mut last_promoted,
                            ),
                            Err(RecvTimeoutError::Timeout) => {}
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                        continue;
                    }
                    Err(error) => {
                        control.record(PipelineStopRecord::Failed {
                            identity: None,
                            reason: retryable("peek next durable job", error),
                            release_error: None,
                        });
                        break;
                    }
                };
                let next_header = match store.get_header(expected_height) {
                    Ok(Some(header)) => header,
                    Ok(None) => {
                        control.record(PipelineStopRecord::Failed {
                            identity: Some(SelectedHistoryJobIdentity::from(next)),
                            reason: retryable_message(
                                "peek next durable job",
                                "canonical successor header is missing",
                            ),
                            release_error: None,
                        });
                        break;
                    }
                    Err(error) => {
                        control.record(PipelineStopRecord::Failed {
                            identity: Some(SelectedHistoryJobIdentity::from(next)),
                            reason: retryable("peek next canonical header", error),
                            release_error: None,
                        });
                        break;
                    }
                };
                if next.height != expected_height
                    || next.block_hash != block_id(&next_header)
                    || next_header.prev_block_hash != tail.block_hash
                {
                    tracing::debug!(
                        height = next.height,
                        tail = tail.height,
                        "selected-history successor is a gap or fork replacement; ending drain"
                    );
                    if in_flight.is_empty() {
                        break;
                    }
                    match done_rx.recv_timeout(PIPELINE_WAIT_TICK) {
                        Ok(completion) => apply_completion(
                            completion,
                            &mut in_flight,
                            &mut promoted,
                            &mut last_promoted,
                        ),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    continue;
                }

                // Memory admission is tied to the head's measured band. A
                // small B8-B64 session must finish and release its 6-GiB lane
                // before claiming a B255 successor; a B255-exclusive session
                // likewise cannot be silently reused for a smaller height.
                if !same_selected_session_band(session_head_tier, next.tier) {
                    tracing::info!(
                        head_tier = ?session_head_tier,
                        next_tier = ?next.tier,
                        "selected-history tier boundary ends the current proof session"
                    );
                    break;
                }

                let tiers: Vec<RecursiveProofJobTier> =
                    in_flight.iter().map(|handoff| handoff.tier).collect();
                let depth = depth_policy(next.tier, &tiers).max(1);
                if in_flight.len() >= depth {
                    match done_rx.recv_timeout(PIPELINE_WAIT_TICK) {
                        Ok(completion) => apply_completion(
                            completion,
                            &mut in_flight,
                            &mut promoted,
                            &mut last_promoted,
                        ),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    continue;
                }

                match claim_next_pipeline_job(store) {
                    Ok(Some(claimed))
                        if claimed.job.height == next.height
                            && claimed.job.block_hash == next.block_hash
                            && claimed.job.tier == next.tier
                            && claimed.job.state == RecursiveProofJobState::Running
                            && claimed.job.attempt_counter
                                == next.attempt_counter.saturating_add(1) =>
                    {
                        pending_claim = Some(claimed);
                    }
                    Ok(Some(mut other)) => {
                        let identity = SelectedHistoryJobIdentity::from(other.job);
                        let release_error = other.release().err();
                        tracing::debug!(
                            job = ?identity,
                            release_error = ?release_error,
                            "selected-history claim raced the peek; ending drain"
                        );
                        break;
                    }
                    Ok(None) => {
                        if in_flight.is_empty() {
                            break;
                        }
                        continue;
                    }
                    Err(reason) => {
                        control.record(PipelineStopRecord::Failed {
                            identity: None,
                            reason,
                            release_error: None,
                        });
                        break;
                    }
                }
            }

            let Some(mut running) = pending_claim.take() else {
                continue;
            };

            let job = running.job;
            let identity = SelectedHistoryJobIdentity::from(job);

            // Stage A: load + replay + Block-prove on the controller thread.
            let claimed_at = running.claimed_at;
            let block_started = Instant::now();
            let block_queue_ms = elapsed_ms(claimed_at);
            let staged = match catch_unwind(AssertUnwindSafe(|| stage_block(&job, &in_flight))) {
                Ok(Ok(staged)) => staged,
                Ok(Err(reason)) => {
                    record_stage_failure(control, &mut running, identity, reason);
                    break;
                }
                Err(_) => {
                    record_stage_failure(
                        control,
                        &mut running,
                        identity,
                        SelectedHistoryWorkerBackoff::Panicked,
                    );
                    break;
                }
            };
            let block_ms = elapsed_ms(block_started);
            let block_ready_at = Instant::now();
            let handoff = PipelineHandoff {
                height: job.height,
                block_hash: job.block_hash,
                tier: job.tier,
                end_accumulator: staged.end_accumulator,
                ladder_update: Arc::clone(&staged.ladder_update),
            };
            drain_tail = Some(identity);
            in_flight.push(handoff);

            let mut unit = LinkLaneUnit {
                running,
                identity,
                payload: staged.payload,
                claimed_at,
                block_ready_at,
                block_queue_ms,
                block_ms,
                ladder_update: staged.ladder_update,
            };
            loop {
                match link_tx.try_send(unit) {
                    Ok(()) => break,
                    Err(TrySendError::Full(returned)) => {
                        unit = returned;
                        if control.stopping() || cancelled.load(Ordering::Acquire) {
                            // The guard inside the unit releases the claim.
                            if cancelled.load(Ordering::Acquire) && !control.stopping() {
                                record_stage_failure(
                                    control,
                                    &mut unit.running,
                                    identity,
                                    SelectedHistoryWorkerBackoff::Cancelled,
                                );
                            }
                            drop(unit);
                            break 'controller;
                        }
                        match done_rx.recv_timeout(PIPELINE_WAIT_TICK) {
                            Ok(completion) => apply_completion(
                                completion,
                                &mut in_flight,
                                &mut promoted,
                                &mut last_promoted,
                            ),
                            Err(RecvTimeoutError::Timeout) => {}
                            Err(RecvTimeoutError::Disconnected) => {
                                drop(unit);
                                break 'controller;
                            }
                        }
                    }
                    Err(TrySendError::Disconnected(returned)) => {
                        // The lane recorded its own stop reason before
                        // exiting; the returned guard releases the claim.
                        drop(returned);
                        break 'controller;
                    }
                }
            }
        }

        drop(link_tx);
        // Both lanes drain their queues (releasing or finishing units) and
        // exit on disconnect; collect every remaining completion.
        while let Ok(completion) = done_rx.recv() {
            apply_completion(
                completion,
                &mut in_flight,
                &mut promoted,
                &mut last_promoted,
            );
        }
        link_handle
            .join()
            .expect("selected-history Link lane panicked outside its stage boundary")
    });

    PipelineRunSummary {
        promoted,
        last_promoted,
        stop: control.into_record(),
        tail_package,
    }
}

/// Stage B lane: selected Link proofs strictly in claim order, each chaining
/// on the previous package this lane itself produced (or the durable
/// predecessor resolved by stage A at the pipeline head).
fn link_lane<'a, TB, TV, TL, SL>(
    control: &PipelineControl,
    cancelled: &AtomicBool,
    link_rx: Receiver<LinkLaneUnit<'a, TB>>,
    verify_tx: SyncSender<VerifyLaneUnit<'a, TV>>,
    stage_link: &mut SL,
) -> Option<InPipelinePackage<TL>>
where
    SL: FnMut(
        &RecursiveProofJob,
        Option<InPipelinePackage<TL>>,
        TB,
    ) -> Result<LinkStageResult<TV, TL>, SelectedHistoryWorkerBackoff>,
{
    let mut last_package: Option<InPipelinePackage<TL>> = None;
    while let Ok(unit) = link_rx.recv() {
        if control.discards(unit.identity.height) {
            // Downstream of a recorded stop: discard silently, the dropped
            // guard releases the claim.
            continue;
        }
        let LinkLaneUnit {
            mut running,
            identity,
            payload,
            claimed_at,
            block_ready_at,
            block_queue_ms,
            block_ms,
            ladder_update,
        } = unit;
        if cancelled.load(Ordering::Acquire) {
            record_stage_failure(
                control,
                &mut running,
                identity,
                SelectedHistoryWorkerBackoff::Cancelled,
            );
            continue;
        }
        let job = running.job;
        // The private local replay authority is linear: remove the previous
        // package from the lane before entering stage B. Success replaces it
        // with height N's capsule; failure drops it and collapses the drain.
        let in_pipeline = last_package
            .take()
            .filter(|package| package.height.checked_add(1) == Some(job.height));
        let started = Instant::now();
        let link_queue_ms = elapsed_ms(block_ready_at);
        let staged = match catch_unwind(AssertUnwindSafe(|| stage_link(&job, in_pipeline, payload)))
        {
            Ok(Ok(staged)) => staged,
            Ok(Err(reason)) => {
                record_stage_failure(control, &mut running, identity, reason);
                continue;
            }
            Err(_) => {
                record_stage_failure(
                    control,
                    &mut running,
                    identity,
                    SelectedHistoryWorkerBackoff::Panicked,
                );
                continue;
            }
        };
        let link_ms = elapsed_ms(started);
        let verify_ready_at = Instant::now();
        last_package = Some(InPipelinePackage {
            height: job.height,
            block_hash: job.block_hash,
            encoded: Arc::clone(&staged.encoded_package),
            local_replay: staged.local_replay,
        });
        let unit = VerifyLaneUnit {
            running,
            identity,
            payload: staged.payload,
            encoded_package: staged.encoded_package,
            claimed_at,
            verify_ready_at,
            block_queue_ms,
            block_ms,
            link_queue_ms,
            link_ms,
            ladder_update,
        };
        if verify_tx.send(unit).is_err() {
            // The verify lane never exits before its channel drains unless
            // the pipeline is already stopping; the rejected unit's guard
            // released the claim on drop.
            if !control.stopping() {
                control.record(PipelineStopRecord::Failed {
                    identity: Some(identity),
                    reason: retryable_message(
                        "hand terminal package to verify lane",
                        "verify lane exited before the pipeline drained",
                    ),
                    release_error: None,
                });
            }
        }
    }
    last_package
}

/// Stage C lane: stream-verify and atomically promote strictly in claim
/// order.  The store's exact-predecessor coverage check remains the final
/// ordering and reorg authority.
fn verify_lane<'a, TV, SV>(
    store: &MdbxStore,
    control: &PipelineControl,
    cancelled: &AtomicBool,
    verify_rx: Receiver<VerifyLaneUnit<'a, TV>>,
    done_tx: mpsc::Sender<PipelineCompletion>,
    previous_promoted_at: &mut Option<Instant>,
    stage_verify: &mut SV,
) where
    SV: FnMut(&RecursiveProofJob, &TV) -> Result<(), SelectedHistoryWorkerBackoff>,
{
    while let Ok(unit) = verify_rx.recv() {
        if control.discards(unit.identity.height) {
            continue; // dropped guard releases the claim
        }
        let VerifyLaneUnit {
            mut running,
            identity,
            payload,
            encoded_package,
            claimed_at,
            verify_ready_at,
            block_queue_ms,
            block_ms,
            link_queue_ms,
            link_ms,
            ladder_update,
        } = unit;
        if cancelled.load(Ordering::Acquire) {
            record_stage_failure(
                control,
                &mut running,
                identity,
                SelectedHistoryWorkerBackoff::Cancelled,
            );
            continue;
        }
        let job = running.job;
        let started = Instant::now();
        let verify_queue_ms = elapsed_ms(verify_ready_at);
        match catch_unwind(AssertUnwindSafe(|| stage_verify(&job, &payload))) {
            Ok(Ok(())) => {}
            Ok(Err(reason)) => {
                record_stage_failure(control, &mut running, identity, reason);
                continue;
            }
            Err(_) => {
                record_stage_failure(
                    control,
                    &mut running,
                    identity,
                    SelectedHistoryWorkerBackoff::Panicked,
                );
                continue;
            }
        }
        let verify_ms = elapsed_ms(started);
        if cancelled.load(Ordering::Acquire) {
            record_stage_failure(
                control,
                &mut running,
                identity,
                SelectedHistoryWorkerBackoff::Cancelled,
            );
            continue;
        }

        let promote_started = Instant::now();
        match running.promote(encoded_package.as_slice(), &ladder_update) {
            Ok(()) => {
                let promote_ms = elapsed_ms(promote_started);
                let promoted_at = Instant::now();
                let cadence_ms = previous_promoted_at.map(elapsed_ms);
                let memory = noid_core::mem_profile::current_mem_snapshot();
                let rss_mib = memory.map(|snapshot| snapshot.rss_kib / 1024);
                let hwm_mib = memory.map(|snapshot| snapshot.hwm_kib / 1024);
                *previous_promoted_at = Some(promoted_at);
                tracing::info!(
                    height = identity.height,
                    hash = %hex::encode(identity.block_hash),
                    tier = ?job.tier,
                    block_queue_ms,
                    block_ms,
                    link_queue_ms,
                    link_ms,
                    verify_queue_ms,
                    verify_ms,
                    promote_ms,
                    e2e_ms = elapsed_ms(claimed_at),
                    cadence_ms = ?cadence_ms,
                    rss_mib = ?rss_mib,
                    hwm_mib = ?hwm_mib,
                    "selected-history terminal promoted"
                );
                if done_tx.send(PipelineCompletion { identity }).is_err() {
                    // The controller drains completions until disconnect; a
                    // failed send only happens after the scope is unwinding.
                    return;
                }
            }
            Err(error) => {
                let superseded = canonical_coverage_supersedes(store, identity);
                if superseded {
                    // Someone else (e.g. a verified terminal import) already
                    // covers this height: discard the pipeline silently and
                    // let the next poll re-claim from durable coverage.
                    tracing::info!(
                        height = identity.height,
                        hash = %hex::encode(identity.block_hash),
                        "selected-history terminal superseded by advanced coverage; discarding pipelined work"
                    );
                    control.record(PipelineStopRecord::Superseded { identity });
                    // The guard's drop attempts the release; a job already
                    // covered or replaced may legitimately refuse it.
                } else {
                    let release_error = running.release().err();
                    control.record(PipelineStopRecord::Failed {
                        identity: Some(identity),
                        reason: retryable("atomically promote selected terminal", error),
                        release_error,
                    });
                }
                continue;
            }
        }
    }
}

/// Classify a failed promote as a benign race only when the durable coverage
/// has actually advanced to a canonical header at or above this job. This
/// deliberately does not treat an arbitrary store/decode error as a remote
/// import race.
fn canonical_coverage_supersedes(store: &MdbxStore, identity: SelectedHistoryJobIdentity) -> bool {
    let Ok(Some(coverage)) = store.get_selected_history_coverage() else {
        return false;
    };
    if coverage.height < identity.height {
        return false;
    }
    store
        .get_header(coverage.height)
        .ok()
        .flatten()
        .is_some_and(|header| block_id(&header) == coverage.block_hash)
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Production stages
// ---------------------------------------------------------------------------

/// Stage A output: everything the Link stage needs for exactly one height.
struct ProvenBlockStage {
    parent_header: BlockHeader,
    block_header: BlockHeader,
    /// The accumulator the replay started from; a pipelined Link stage must
    /// re-derive exactly this value from the predecessor package bytes.
    start_accumulator: ChainAccumulator,
    /// The ten-lane end identity produced by native replay; the streaming
    /// verifier must reproduce it before promotion.
    expected_end_accumulator: ChainAccumulator,
    /// `Some` when stage A resolved the predecessor durably (pipeline head or
    /// genesis); `None` when the predecessor package is still in flight and
    /// must come from the Link lane's own previous output.
    resolved_predecessor: Option<SelectedRecursiveLinkPredecessor>,
    /// The retained predecessor capability from the previous proof session
    /// matched exact coverage and result bytes in this Stage-A MDBX snapshot.
    cross_session_tail_matches_durable: bool,
    current_block: SelectedRecursiveBlockProof,
}

/// Stage B output consumed by terminal verification.
struct VerifiableTerminalStage {
    block_header: BlockHeader,
    package: SelectedHistoryTerminalPackage,
    expected_end_accumulator: ChainAccumulator,
}

#[allow(clippy::too_many_arguments)]
fn stage_replay_and_prove_block<S: SelectedRecursiveMatrixSource + Send>(
    store: &MdbxStore,
    registry: &LoadedSelectedRecursiveClassRegistry,
    block_classes: &SelectedRecursiveBlockClasses<'_>,
    link_classes: &SelectedRecursiveLinkClasses<'_>,
    session: &SelectedHistoryProofSession,
    matrix_source: &mut S,
    cancelled: &AtomicBool,
    job: &RecursiveProofJob,
    handoffs: &[PipelineHandoff],
    expected_cross_session_tail: Option<&CrossSessionTailExpectation>,
) -> Result<BlockStageResult<ProvenBlockStage>, SelectedHistoryWorkerBackoff> {
    check_cancelled(cancelled)?;
    let claimed = *job;

    // A present handoff means this pipeline still owns the Running
    // predecessor claim; the loader then admits it and defers its result.
    let loaded = if handoffs.is_empty() {
        match expected_cross_session_tail {
            Some(expected) => store
                .load_claimed_recursive_proof_job_inputs_with_expected_predecessor(
                    claimed,
                    expected.height,
                    expected.block_hash,
                    expected.encoded.as_slice(),
                ),
            None => store
                .load_claimed_recursive_proof_job_inputs(claimed)
                .map(|inputs| (inputs, false)),
        }
    } else {
        store
            .load_claimed_recursive_proof_job_inputs_with_running_predecessor(claimed)
            .map(|inputs| (inputs, false))
    };
    let (inputs, cross_session_tail_matches_durable) =
        loaded.map_err(|error| retryable("load one claimed MDBX snapshot", error))?;
    if expected_cross_session_tail.is_some() {
        tracing::info!(
            height = claimed.height,
            cross_session_tail_matches_durable,
            "selected-history cross-session tail checked in Stage-A snapshot"
        );
    }
    check_cancelled(cancelled)?;

    let noid_chain::storage::ClaimedRecursiveProofJobInputs {
        job,
        source_tip: _,
        parent_header,
        block_header,
        user_transaction_count,
        block_bytes,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        previous_result,
    } = inputs;
    if job != claimed {
        return Err(retryable_message(
            "validate claimed snapshot",
            "loaded job differs from the durable claim",
        ));
    }
    let in_memory_parent = match handoffs.last() {
        Some(handoff)
            if handoff.height == job.height.saturating_sub(1)
                && handoff.block_hash == block_id(&parent_header) =>
        {
            Some(handoff)
        }
        Some(_) => {
            return Err(retryable_message(
                "resolve pipelined predecessor",
                "in-memory predecessor cursor does not match the claimed canonical parent",
            ));
        }
        None => None,
    };

    let current_tier = selected_recursive_tier(user_transaction_count)
        .map_err(|error| retryable("select recursive Block tier", error))?;
    if !storage_tier_matches(job.tier, current_tier) {
        return Err(retryable_message(
            "validate claimed snapshot",
            "durable tier differs from the canonical transaction-count tier",
        ));
    }

    let block = Block::from_bytes(&block_bytes)
        .map_err(|error| retryable("decode retained block", error))?;
    drop(block_bytes);
    if block.header != block_header
        || block_id(&block.header) != job.block_hash
        || block
            .transactions
            .iter()
            .filter(|transaction| !transaction.body.is_coinbase)
            .count()
            != user_transaction_count
    {
        return Err(retryable_message(
            "validate retained block",
            "decoded block identity or user transaction count mismatch",
        ));
    }
    let required_segment_ids = derive_touched_segment_ids(&block, parent_header.log_slots)
        .map_err(|error| retryable("derive touched exact-state segments", error))?;
    check_cancelled(cancelled)?;

    let start_consensus = recursive_consensus_state_at_header(store, &parent_header)?;
    let (start_accumulator, resolved_predecessor) = match previous_result {
        Some(previous_result) => {
            let (accumulator, predecessor) = predecessor_from_result(
                registry,
                job.height,
                &parent_header,
                Some(previous_result),
            )?;
            if in_memory_parent.is_some_and(|handoff| handoff.end_accumulator != accumulator) {
                return Err(retryable_message(
                    "resolve pipelined predecessor",
                    "durable predecessor differs from the in-memory replay cursor",
                ));
            }
            (accumulator, Some(predecessor))
        }
        None if job.height == 1 => {
            let (accumulator, predecessor) =
                predecessor_from_result(registry, job.height, &parent_header, None)?;
            (accumulator, Some(predecessor))
        }
        None => {
            // The predecessor is still in flight in this same pipeline: its
            // replay's end accumulator is the exact start cursor, and its
            // package bytes are resolved later by the Link lane and
            // cross-checked against this value.
            let handoff = in_memory_parent.ok_or_else(|| {
                retryable_message(
                    "resolve pipelined predecessor",
                    "non-genesis job has neither durable nor in-memory predecessor",
                )
            })?;
            (handoff.end_accumulator.clone(), None)
        }
    };
    validate_start_accumulator(store, &start_accumulator, &parent_header)?;
    check_cancelled(cancelled)?;

    // The head hydrates from the durable forward cursor. A non-head height
    // layers every still-unpromoted update oldest-first over that cursor, so
    // a segment dirtied at N and untouched at N+1 is still available to N+2.
    let start_state = if handoffs.is_empty() {
        load_selected_history_ladder_parent_state(store, &parent_header, &required_segment_ids)
            .map_err(|error| retryable("load forward ladder parent state", error))?
    } else {
        let updates: Vec<&SelectedHistoryLadderUpdate> = handoffs
            .iter()
            .map(|handoff| handoff.ladder_update.as_ref())
            .collect();
        load_selected_history_pipelined_parent_state(
            store,
            &parent_header,
            &updates,
            &required_segment_ids,
        )
        .map_err(|error| retryable("load pipelined ladder parent state", error))?
    };
    check_cancelled(cancelled)?;

    let (artifacts, ladder_update) = noid_miner::install_selected_history_cpu(
        noid_miner::SelectedHistoryCpuStage::Block,
        || {
            reconstruct_selected_recursive_block_artifacts(
                start_consensus,
                start_accumulator.clone(),
                parent_header,
                start_state,
                FullAcceptedBlockBatchItem {
                    block,
                    block_proof_bytes,
                    block_auth_sidecar_bytes,
                },
            )
        },
    )
    .map_err(|error| retryable("enter selected Block CPU pool", error))?
    .map_err(|error| retryable("reconstruct selected Block artifacts", error))?;
    check_cancelled(cancelled)?;
    // Keep only the fixed terminal identity. The consuming job moves
    // every B255-sized component/proof vector into Block construction.
    let expected_end_accumulator = artifacts.end_accumulator().clone();

    let current_block = session
        .prove_block_pipelined_with_matrices(
            block_classes,
            link_classes,
            SelectedRecursiveBlockJob::from_native_verified(artifacts),
            matrix_source,
        )
        .map_err(|error| retryable("prove selected Block", error))?;

    // The consuming Block job drops its B255-sized retained carrier before
    // Link proving; only the standalone Block envelope crosses this boundary.
    check_cancelled(cancelled)?;

    Ok(BlockStageResult {
        end_accumulator: expected_end_accumulator.clone(),
        ladder_update: Arc::new(ladder_update),
        payload: ProvenBlockStage {
            parent_header,
            block_header,
            start_accumulator,
            expected_end_accumulator,
            resolved_predecessor,
            cross_session_tail_matches_durable,
            current_block,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn stage_link_and_package<S: SelectedRecursiveMatrixSource + Send>(
    registry: &LoadedSelectedRecursiveClassRegistry,
    link_classes: &SelectedRecursiveLinkClasses<'_>,
    session: &SelectedHistoryProofSession,
    matrix_source: &mut S,
    cancelled: &AtomicBool,
    job: &RecursiveProofJob,
    in_pipeline: Option<InPipelinePackage<SelectedRecursiveLocalLinkReplay>>,
    staged: ProvenBlockStage,
) -> Result<
    LinkStageResult<VerifiableTerminalStage, SelectedRecursiveLocalLinkReplay>,
    SelectedHistoryWorkerBackoff,
> {
    let stage_started = Instant::now();
    check_cancelled(cancelled)?;
    let ProvenBlockStage {
        parent_header,
        block_header,
        start_accumulator,
        expected_end_accumulator,
        resolved_predecessor,
        cross_session_tail_matches_durable: _,
        current_block,
    } = staged;

    let predecessor_started = Instant::now();
    let predecessor = match in_pipeline {
        Some(in_pipeline) => {
            // Chain on the exact bytes the predecessor's promote persists.
            // This is either the immediately preceding lane output or the
            // bit-identical promoted tail retained across a session yield.
            if in_pipeline.height != job.height.saturating_sub(1)
                || in_pipeline.block_hash != block_id(&parent_header)
            {
                return Err(retryable_message(
                    "resolve pipelined predecessor",
                    "in-memory predecessor package does not match the canonical parent",
                ));
            }
            let InPipelinePackage {
                encoded,
                local_replay,
                ..
            } = in_pipeline;
            let (accumulator, predecessor) =
                predecessor_from_terminal_bytes(registry, &parent_header, &encoded)?;
            if accumulator != start_accumulator {
                return Err(retryable_message(
                    "resolve pipelined predecessor",
                    "in-memory predecessor package accumulator differs from the replayed cursor",
                ));
            }
            local_replay
                .bind_decoded_predecessor(predecessor)
                .map_err(|error| retryable("bind local predecessor replay", error))?
        }
        None => resolved_predecessor.ok_or_else(|| {
            retryable_message(
                "resolve pipelined predecessor",
                "non-head Link has neither a local replay nor a durable predecessor",
            )
        })?,
    };
    let predecessor_resolve_ms = elapsed_ms(predecessor_started);

    let prover_started = Instant::now();
    let linked = session
        .prove_link_pipelined(
            link_classes,
            SelectedRecursiveLinkJob {
                predecessor,
                current_block,
            },
            matrix_source,
        )
        .map_err(|error| retryable("prove selected Link", error))?;
    let link_prover_total_ms = elapsed_ms(prover_started);
    check_cancelled(cancelled)?;

    let package_started = Instant::now();
    let (linked_tier, linked_envelope, local_replay) = linked
        .into_pipelined_parts()
        .map_err(|error| retryable("retain local Link replay", error))?;
    let tip_slot = selected_tier_slot(linked_tier);
    let package =
        SelectedHistoryTerminalPackage::new(job.height, job.block_hash, tip_slot, linked_envelope)
            .map_err(|error| retryable("construct selected terminal package", error))?;
    let encoded_package = package
        .encode()
        .map_err(|error| retryable("encode selected terminal package", error))?;
    let terminal_package_encode_ms = elapsed_ms(package_started);
    tracing::info!(
        height = job.height,
        predecessor_resolve_ms,
        link_prover_total_ms,
        terminal_package_encode_ms,
        link_stage_total_ms = elapsed_ms(stage_started),
        "selected-history Link stage phases"
    );

    Ok(LinkStageResult {
        encoded_package: Arc::new(encoded_package),
        local_replay,
        payload: VerifiableTerminalStage {
            block_header,
            package,
            expected_end_accumulator,
        },
    })
}

fn stage_verify_terminal<S: SelectedHistoryMatrixSource + Send>(
    store: &MdbxStore,
    registry: &LoadedSelectedRecursiveClassRegistry,
    matrix_source: &mut S,
    cancelled: &AtomicBool,
    job: &RecursiveProofJob,
    staged: &VerifiableTerminalStage,
) -> Result<(), SelectedHistoryWorkerBackoff> {
    check_cancelled(cancelled)?;
    if staged.block_header.height != job.height || block_id(&staged.block_header) != job.block_hash
    {
        return Err(retryable_message(
            "promote selected terminal",
            "verified package identity changed before promotion",
        ));
    }

    // Prepare the two small local authorities while proof admission is still
    // held by the surrounding pipeline session.
    let epoch_height = (staged.block_header.height / TX_EPOCH_BLOCKS) * TX_EPOCH_BLOCKS;
    let epoch_anchor_header = store
        .get_header(epoch_height)
        .map_err(|error| retryable("read terminal epoch anchor", error))?
        .ok_or_else(|| {
            retryable_message(
                "read terminal epoch anchor",
                "canonical epoch-anchor header is missing",
            )
        })?;
    let terminal_registry = registry.terminal_registry();

    let verified_accumulator = noid_miner::install_selected_history_cpu(
        noid_miner::SelectedHistoryCpuStage::Verify,
        || {
            noid_recursive::verify_selected_history_terminal(
                &staged.package,
                &terminal_registry,
                &staged.block_header,
                &epoch_anchor_header,
                matrix_source,
            )
        },
    )
    .map_err(|error| retryable("enter selected Verify CPU pool", error))?
    .map_err(|error| retryable("stream-verify selected terminal", error))?;
    if verified_accumulator != staged.expected_end_accumulator {
        return Err(retryable_message(
            "validate terminal accumulator",
            "streaming verifier result differs from accepted Block reconstruction",
        ));
    }
    check_cancelled(cancelled)
}

// ---------------------------------------------------------------------------
// Durable claim guard and shared helpers
// ---------------------------------------------------------------------------

/// Armed immediately after Pending -> Running and disarmed only by the same
/// transaction that completes/promotes the locally verified package.
/// Unwind, early return, cancellation and ordinary errors all return the job
/// to Pending.  A reorg may make release fail because the hash is no longer
/// canonical; that stale job is then handled by the store's canonical queue
/// maintenance rather than rewritten under a different hash.
struct RunningJobGuard<'a> {
    store: &'a MdbxStore,
    job: RecursiveProofJob,
    armed: bool,
    claimed_at: Instant,
}

impl<'a> RunningJobGuard<'a> {
    fn new(store: &'a MdbxStore, job: RecursiveProofJob) -> Self {
        let armed = job.state == RecursiveProofJobState::Running;
        Self {
            store,
            job,
            armed,
            claimed_at: Instant::now(),
        }
    }

    fn release(&mut self) -> Result<(), String> {
        if !self.armed {
            return Ok(());
        }
        self.store
            .release_recursive_proof_job(self.job.height, self.job.block_hash)
            .map_err(|error| error.to_string())?;
        self.armed = false;
        Ok(())
    }

    fn promote(
        &mut self,
        encoded_package: &[u8],
        ladder_update: &SelectedHistoryLadderUpdate,
    ) -> Result<(), String> {
        self.store
            .complete_recursive_proof_job_and_promote_selected_history(
                self.job.height,
                self.job.block_hash,
                encoded_package,
                ladder_update,
            )
            .map_err(|error| error.to_string())?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for RunningJobGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = self
                .store
                .release_recursive_proof_job(self.job.height, self.job.block_hash)
            {
                tracing::warn!(
                    height = self.job.height,
                    hash = %hex::encode(self.job.block_hash),
                    err = %error,
                    "selected-history unpromoted job release failed during guard drop"
                );
            }
        }
    }
}

fn release_backoff(
    running: &mut RunningJobGuard<'_>,
    identity: SelectedHistoryJobIdentity,
    reason: SelectedHistoryWorkerBackoff,
) -> SelectedHistoryWorkerOutcome {
    let release_error = running.release().err();
    backoff(Some(identity), reason, release_error)
}

fn backoff(
    job: Option<SelectedHistoryJobIdentity>,
    reason: SelectedHistoryWorkerBackoff,
    release_error: Option<String>,
) -> SelectedHistoryWorkerOutcome {
    SelectedHistoryWorkerOutcome::Backoff {
        job,
        reason,
        release_error,
    }
}

fn validate_start_accumulator(
    store: &MdbxStore,
    start_accumulator: &ChainAccumulator,
    parent_header: &BlockHeader,
) -> Result<(), SelectedHistoryWorkerBackoff> {
    let epoch_height = (parent_header.height / TX_EPOCH_BLOCKS) * TX_EPOCH_BLOCKS;
    let epoch_anchor_header = store
        .get_header(epoch_height)
        .map_err(|error| retryable("read predecessor epoch anchor", error))?
        .ok_or_else(|| {
            retryable_message(
                "read predecessor epoch anchor",
                "canonical predecessor epoch-anchor header is missing",
            )
        })?;
    start_accumulator
        .validate_local_header_boundary(parent_header, &epoch_anchor_header)
        .map_err(|error| retryable("validate predecessor accumulator boundary", error))
}

fn predecessor_from_result(
    registry: &LoadedSelectedRecursiveClassRegistry,
    height: u64,
    parent_header: &BlockHeader,
    previous_result: Option<noid_chain::storage::RecursiveProofJobResult>,
) -> Result<(ChainAccumulator, SelectedRecursiveLinkPredecessor), SelectedHistoryWorkerBackoff> {
    if height == 1 {
        if previous_result.is_some() {
            return Err(retryable_message(
                "decode recursive predecessor",
                "height-one job unexpectedly carries a previous result",
            ));
        }
        return Ok((
            genesis_accumulator(),
            SelectedRecursiveLinkPredecessor::Genesis,
        ));
    }

    let previous_result = previous_result.ok_or_else(|| {
        retryable_message(
            "decode recursive predecessor",
            "non-genesis job is missing its completed predecessor",
        )
    })?;
    if previous_result.height != height - 1 || previous_result.block_hash != block_id(parent_header)
    {
        return Err(retryable_message(
            "decode recursive predecessor",
            "previous result identity does not match the parent header",
        ));
    }
    let decoded = predecessor_from_terminal_bytes(registry, parent_header, &previous_result.bytes);
    drop(previous_result);
    decoded
}

/// Decode and validate one predecessor terminal package.  The pipelined and
/// durable predecessor paths share this exact implementation, so chaining on
/// in-memory bytes is bit-for-bit the same authority as reading the promoted
/// MDBX result.
fn predecessor_from_terminal_bytes(
    registry: &LoadedSelectedRecursiveClassRegistry,
    parent_header: &BlockHeader,
    bytes: &[u8],
) -> Result<(ChainAccumulator, SelectedRecursiveLinkPredecessor), SelectedHistoryWorkerBackoff> {
    let package = decode_selected_history_terminal_package(bytes)
        .map_err(|error| retryable("decode recursive predecessor", error))?;
    if package.terminal_height() != parent_header.height
        || package.terminal_hash() != block_id(parent_header)
    {
        return Err(retryable_message(
            "decode recursive predecessor",
            "previous terminal metadata does not match the parent header",
        ));
    }
    let slot = package.canonical_tip_slot();
    let tier = selected_tier_from_slot(slot).ok_or_else(|| {
        retryable_message(
            "decode recursive predecessor",
            "previous terminal selected an unknown canonical slot",
        )
    })?;
    let class = registry.owned().link_classes().get(slot).ok_or_else(|| {
        retryable_message(
            "decode recursive predecessor",
            "compact registry is missing the previous Link class",
        )
    })?;
    let accumulator = tip_block_accumulator_split(class, package.terminal_envelope())
        .map_err(|error| retryable("decode recursive predecessor accumulator", error))?;
    Ok((
        accumulator,
        SelectedRecursiveLinkPredecessor::Previous {
            tier,
            envelope: package.into_terminal_envelope(),
        },
    ))
}

fn recursive_consensus_state_at_header(
    store: &MdbxStore,
    expected_header: &BlockHeader,
) -> Result<RecursiveConsensusState, SelectedHistoryWorkerBackoff> {
    let height = expected_header.height;
    let header = store
        .get_header(height)
        .map_err(|error| retryable("read recursive start header", error))?
        .ok_or_else(|| {
            retryable_message(
                "read recursive start header",
                "canonical start header is missing",
            )
        })?;
    if &header != expected_header || block_id(&header) != block_id(expected_header) {
        return Err(retryable_message(
            "read recursive start header",
            "canonical start header changed after the claimed snapshot",
        ));
    }
    let cumulative_chainwork = store
        .get_chain_work(height)
        .map_err(|error| retryable("read recursive start chainwork", error))?
        .ok_or_else(|| {
            retryable_message(
                "read recursive start chainwork",
                "canonical start chainwork is missing",
            )
        })?;

    let timestamp_start = height.saturating_sub(MEDIAN_TIME_BLOCKS as u64 - 1);
    let timestamp_len = usize::try_from(height - timestamp_start + 1)
        .expect("MTP window length is protocol bounded");
    let mut timestamps = [0u64; MEDIAN_TIME_BLOCKS];
    for (offset, at_height) in (timestamp_start..=height).enumerate() {
        timestamps[offset] = store
            .get_header(at_height)
            .map_err(|error| retryable("read recursive MTP header", error))?
            .ok_or_else(|| {
                retryable_message(
                    "read recursive MTP header",
                    "canonical MTP header is missing",
                )
            })?
            .timestamp;
    }

    const EXPANSION_WINDOW_LEN: usize = EXPANSION_WINDOW as usize;
    let active_start = height.saturating_sub(EXPANSION_WINDOW.saturating_sub(1));
    let active_len = usize::try_from(height - active_start + 1)
        .expect("expansion window length is protocol bounded");
    let mut active_counts = [0u64; EXPANSION_WINDOW_LEN];
    for (offset, at_height) in (active_start..=height).enumerate() {
        active_counts[offset] = store
            .get_header(at_height)
            .map_err(|error| retryable("read recursive expansion header", error))?
            .ok_or_else(|| {
                retryable_message(
                    "read recursive expansion header",
                    "canonical expansion header is missing",
                )
            })?
            .active_slot_count;
    }

    let anchor_height = asert_anchor_height(height);
    let anchor_header = store
        .get_header(anchor_height)
        .map_err(|error| retryable("read recursive ASERT anchor", error))?
        .ok_or_else(|| {
            retryable_message(
                "read recursive ASERT anchor",
                "canonical ASERT anchor header is missing",
            )
        })?;
    Ok(RecursiveConsensusState::from_header(
        &header,
        cumulative_chainwork,
        anchor_height,
        anchor_header.timestamp,
        anchor_header.difficulty_target,
        &timestamps[..timestamp_len],
        &active_counts[..active_len],
    ))
}

fn storage_tier_matches(storage: RecursiveProofJobTier, selected: SelectedRecursiveTier) -> bool {
    matches!(
        (storage, selected),
        (RecursiveProofJobTier::B8, SelectedRecursiveTier::B8)
            | (RecursiveProofJobTier::B32, SelectedRecursiveTier::B32)
            | (RecursiveProofJobTier::B64, SelectedRecursiveTier::B64)
            | (RecursiveProofJobTier::B255, SelectedRecursiveTier::B255)
    )
}

fn selected_tier_from_storage(storage: RecursiveProofJobTier) -> SelectedRecursiveTier {
    match storage {
        RecursiveProofJobTier::B8 => SelectedRecursiveTier::B8,
        RecursiveProofJobTier::B32 => SelectedRecursiveTier::B32,
        RecursiveProofJobTier::B64 => SelectedRecursiveTier::B64,
        RecursiveProofJobTier::B255 => SelectedRecursiveTier::B255,
    }
}

fn same_selected_session_band(left: RecursiveProofJobTier, right: RecursiveProofJobTier) -> bool {
    let left_b255 = left == RecursiveProofJobTier::B255;
    let right_b255 = right == RecursiveProofJobTier::B255;
    left_b255 == right_b255
}

fn selected_tier_slot(tier: SelectedRecursiveTier) -> usize {
    match tier {
        SelectedRecursiveTier::B8 => 0,
        SelectedRecursiveTier::B32 => 1,
        SelectedRecursiveTier::B64 => 2,
        SelectedRecursiveTier::B255 => 3,
    }
}

fn selected_tier_from_slot(slot: usize) -> Option<SelectedRecursiveTier> {
    match slot {
        0 => Some(SelectedRecursiveTier::B8),
        1 => Some(SelectedRecursiveTier::B32),
        2 => Some(SelectedRecursiveTier::B64),
        3 => Some(SelectedRecursiveTier::B255),
        _ => None,
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), SelectedHistoryWorkerBackoff> {
    if cancelled.load(Ordering::Acquire) {
        Err(SelectedHistoryWorkerBackoff::Cancelled)
    } else {
        Ok(())
    }
}

fn map_prover_admission(error: SelectedRecursiveProverError) -> SelectedHistoryWorkerBackoff {
    match error {
        SelectedRecursiveProverError::ProofStageBusy => {
            SelectedHistoryWorkerBackoff::ProofStageBusy
        }
        other => retryable("acquire selected-history proof session", other),
    }
}

fn retryable(phase: &'static str, error: impl std::fmt::Debug) -> SelectedHistoryWorkerBackoff {
    SelectedHistoryWorkerBackoff::RetryableFailure {
        phase,
        detail: format!("{error:?}"),
    }
}

fn retryable_message(phase: &'static str, detail: &str) -> SelectedHistoryWorkerBackoff {
    SelectedHistoryWorkerBackoff::RetryableFailure {
        phase,
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::genesis::genesis_header;
    use noid_chain::storage::TouchedSegmentError;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Barrier};

    fn transaction(
        input_slot: u32,
        input_live: bool,
        output_slot: u32,
        output_live: bool,
        coinbase: bool,
    ) -> Transaction {
        let mut inputs = [TxInput::dummy(); noid_tx::TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount: 1,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); noid_tx::TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount: 1,
            owner: Address([7u8; 32]),
        };
        let validity_bitmap =
            u16::from(input_live) | if output_live { output_bitmap_bit(0) } else { 0 };
        Transaction::new(TxBody {
            epoch_anchor: [1u8; 32],
            fee: 0,
            input_owner: Address([2u8; 32]),
            inputs,
            outputs,
            validity_bitmap,
            is_coinbase: coinbase,
        })
    }

    /// Canonical header chain 1..=`last_height` on top of genesis, with one
    /// enqueued B8 job per height (skipping heights in `skip`).
    fn enqueue_job_chain(
        store: &MdbxStore,
        last_height: u64,
        skip: &[u64],
    ) -> Vec<(BlockHeader, [u8; 32])> {
        let genesis = genesis_header();
        let genesis_hash = block_id(&genesis);
        store.put_header_only(&genesis, &genesis_hash).unwrap();
        let mut chain = vec![(genesis, genesis_hash)];
        for height in 1..=last_height {
            let (parent, parent_hash) = *chain.last().unwrap();
            let mut header = parent;
            header.height = height;
            header.prev_block_hash = parent_hash;
            header.timestamp = parent.timestamp.saturating_add(1);
            header.nonce = 0x5151 + u128::from(height);
            let hash = block_id(&header);
            store.put_header_only(&header, &hash).unwrap();
            if !skip.contains(&height) {
                store
                    .enqueue_recursive_proof_job(height, hash, RecursiveProofJobTier::B8)
                    .unwrap();
            }
            chain.push((header, hash));
        }
        chain
    }

    fn enqueue_height_one_job(store: &MdbxStore) -> RecursiveProofJob {
        enqueue_job_chain(store, 1, &[]);
        store.get_recursive_proof_job(1).unwrap().unwrap()
    }

    /// Prefix-valid selected terminal bytes for a B8 job; the store validates
    /// exactly this fixed prefix before promotion.
    fn fake_terminal_package_bytes(height: u64, block_hash: [u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(45);
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&block_hash);
        bytes.push(0);
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes
    }

    fn stub_block_stage(
        job: &RecursiveProofJob,
        handoffs: &[PipelineHandoff],
    ) -> Result<BlockStageResult<u64>, SelectedHistoryWorkerBackoff> {
        let _ = handoffs;
        Ok(BlockStageResult {
            payload: job.height,
            end_accumulator: genesis_accumulator(),
            ladder_update: Arc::new(SelectedHistoryLadderUpdate::empty(
                genesis_header().log_slots,
            )),
        })
    }

    fn stub_link_stage(
        job: &RecursiveProofJob,
    ) -> Result<LinkStageResult<u64, ()>, SelectedHistoryWorkerBackoff> {
        Ok(LinkStageResult {
            payload: job.height,
            encoded_package: Arc::new(fake_terminal_package_bytes(job.height, job.block_hash)),
            local_replay: (),
        })
    }

    #[test]
    fn touched_segment_derivation_keeps_only_live_unique_segments() {
        let mut header = genesis_header();
        header.log_slots = 24;
        let block = Block {
            header,
            transactions: vec![
                transaction((3 << 16) + 1, true, (7 << 16) + 2, true, false),
                // Dead fixed-width cells must not hydrate segment 200.
                transaction((200 << 16) + 1, false, (3 << 16) + 9, true, false),
            ],
        };
        assert_eq!(derive_touched_segment_ids(&block, 24).unwrap(), vec![3, 7]);

        let mut monolithic = block;
        monolithic.header.log_slots = 16;
        monolithic.transactions = vec![transaction(9, true, 65_000, true, false)];
        assert_eq!(
            derive_touched_segment_ids(&monolithic, 16).unwrap(),
            vec![0]
        );
    }

    #[test]
    fn touched_segment_derivation_rejects_live_out_of_domain_slot() {
        let mut header = genesis_header();
        header.log_slots = 16;
        let block = Block {
            header,
            transactions: vec![transaction(1 << 16, true, 0, false, false)],
        };
        assert_eq!(
            derive_touched_segment_ids(&block, 16),
            Err(TouchedSegmentError::InputSlotOutOfParentDomain(1 << 16))
        );
    }

    #[test]
    fn expansion_upper_outputs_remain_virtual_and_are_not_hydrated() {
        let mut header = genesis_header();
        header.log_slots = 25;
        let upper_slot = (1 << 24) + 7;
        let block = Block {
            header,
            transactions: vec![transaction((9 << 16) + 1, true, upper_slot, true, false)],
        };
        assert_eq!(
            derive_touched_segment_ids(&block, 24).unwrap(),
            vec![9],
            "the deterministic empty upper half has no parent MDBX payload"
        );
        assert!(matches!(
            derive_touched_segment_ids(&block, 23),
            Err(TouchedSegmentError::InvalidLogSlotsTransition { .. })
        ));
    }

    #[test]
    fn running_job_guard_releases_pending_during_unwind() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        enqueue_height_one_job(&store);
        let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _guard = RunningJobGuard::new(&store, claimed);
            panic!("simulated cancelled proof backend");
        }));
        assert!(unwind.is_err());
        let released = store.get_recursive_proof_job(1).unwrap().unwrap();
        assert_eq!(released.state, RecursiveProofJobState::Pending);
        assert_eq!(released.attempt_counter, 1);
        let reclaimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
        assert_eq!(reclaimed.state, RecursiveProofJobState::Running);
        assert_eq!(reclaimed.attempt_counter, 2);
    }

    #[test]
    fn idle_and_pre_cancelled_polls_never_acquire_admission() {
        for cancelled_at_entry in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let cancelled = AtomicBool::new(cancelled_at_entry);
            let admission_calls = AtomicUsize::new(0);

            let outcome = prepare_pipeline_head_with_admission(&store, &cancelled, |_| {
                admission_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .err()
            .expect("poll must back off before preparation");

            let expected = if cancelled_at_entry {
                SelectedHistoryWorkerBackoff::Cancelled
            } else {
                SelectedHistoryWorkerBackoff::Idle
            };
            assert!(matches!(
                outcome,
                SelectedHistoryWorkerOutcome::Backoff {
                    job: None,
                    reason,
                    release_error: None,
                } if reason == expected
            ));
            assert_eq!(admission_calls.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn cancellation_after_admission_releases_claim_before_any_stage() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let queued = enqueue_height_one_job(&store);
        let cancelled = AtomicBool::new(false);

        let outcome = prepare_pipeline_head_with_admission(&store, &cancelled, |_| {
            cancelled.store(true, Ordering::Release);
            Ok(())
        })
        .err()
        .expect("cancelled preparation must back off");

        assert!(matches!(
            outcome,
            SelectedHistoryWorkerOutcome::Backoff {
                job: Some(identity),
                reason: SelectedHistoryWorkerBackoff::Cancelled,
                release_error: None,
            } if identity == SelectedHistoryJobIdentity::from(queued)
        ));
        let released = store.get_recursive_proof_job(1).unwrap().unwrap();
        assert_eq!(released.state, RecursiveProofJobState::Pending);
        assert_eq!(released.attempt_counter, 1);
    }

    #[test]
    fn pipeline_promotes_consecutive_heights_in_order_with_in_memory_chaining() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = enqueue_job_chain(&store, 3, &[]);
        let cancelled = AtomicBool::new(false);

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        assert_eq!(head.job.height, 1);

        let block_hints = Mutex::new(Vec::new());
        let link_predecessors = Mutex::new(Vec::new());
        let stage_three_ready = Arc::new(Barrier::new(2));
        let stage_three_from_block = Arc::clone(&stage_three_ready);
        let stage_three_from_verify = Arc::clone(&stage_three_ready);
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            |job, handoffs| {
                block_hints.lock().unwrap().push((
                    job.height,
                    handoffs
                        .iter()
                        .map(|handoff| handoff.height)
                        .collect::<Vec<_>>(),
                ));
                if job.height == 3 {
                    stage_three_from_block.wait();
                }
                stub_block_stage(job, handoffs)
            },
            |job, in_pipeline, payload| {
                assert_eq!(payload, job.height, "stage payload follows its unit");
                link_predecessors
                    .lock()
                    .unwrap()
                    .push((job.height, in_pipeline.map(|p| p.height)));
                stub_link_stage(job)
            },
            |job, payload| {
                assert_eq!(*payload, job.height);
                if job.height == 1 {
                    stage_three_from_verify.wait();
                }
                Ok(())
            },
        );

        assert!(summary.stop.is_none(), "stop: {:?}", summary.stop);
        assert_eq!(summary.promoted, 3);
        assert_eq!(
            summary.last_promoted,
            Some(SelectedHistoryJobIdentity {
                height: 3,
                block_hash: chain[3].1,
            })
        );
        // Promotes are strictly ordered by the store's coverage authority.
        assert_eq!(
            store
                .get_selected_history_coverage()
                .unwrap()
                .map(|c| (c.height, c.block_hash)),
            Some((3, chain[3].1))
        );
        for height in 1..=3 {
            let job = store.get_recursive_proof_job(height).unwrap().unwrap();
            assert_eq!(job.state, RecursiveProofJobState::Complete);
        }
        // Height N+1's replay started from N's in-memory cursor, and its
        // Link chained on N's in-memory package.
        assert_eq!(
            block_hints.into_inner().unwrap(),
            vec![(1, vec![]), (2, vec![1]), (3, vec![1, 2])]
        );
        assert_eq!(
            link_predecessors.into_inner().unwrap(),
            vec![(1, None), (2, Some(1)), (3, Some(2))]
        );
    }

    #[test]
    fn cursor_handoff_matches_the_same_boundary_after_promotion() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let genesis = genesis_header();
        let genesis_hash = block_id(&genesis);
        store.put_header_only(&genesis, &genesis_hash).unwrap();
        let mut header = genesis;
        header.height = 1;
        header.prev_block_hash = genesis_hash;
        header.timestamp = header.timestamp.saturating_add(1);
        header.nonce = 0xC0A5_0A;
        header.alloc_counter = 7;
        let hash = block_id(&header);
        store.put_header_only(&header, &hash).unwrap();
        store
            .enqueue_recursive_proof_job(1, hash, RecursiveProofJobTier::B8)
            .unwrap();
        let mut update = SelectedHistoryLadderUpdate::empty(header.log_slots);
        update.alloc_counter = header.alloc_counter;

        // This is the state Stage A(N+1) consumes before N has promoted.
        let in_memory =
            load_selected_history_pipelined_parent_state(&store, &header, &[&update], &[]).unwrap();
        assert_eq!(in_memory.cached_state_root(), header.state_root);
        assert_eq!(in_memory.alloc_counter, 7);

        let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
        assert_eq!(claimed.height, 1);
        store
            .complete_recursive_proof_job_and_promote_selected_history(
                1,
                hash,
                &fake_terminal_package_bytes(1, hash),
                &update,
            )
            .unwrap();

        // Once C promotes N, the durable loader must reconstruct the exact
        // same cursor boundary that was handed to the pipelined replay.
        let durable = load_selected_history_ladder_parent_state(&store, &header, &[]).unwrap();
        assert_eq!(durable.cached_state_root(), in_memory.cached_state_root());
        assert_eq!(durable.active_slot_count, in_memory.active_slot_count);
        assert_eq!(durable.alloc_counter, in_memory.alloc_counter);
    }

    #[test]
    fn link_failure_discards_in_flight_successors_and_reclaims() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = enqueue_job_chain(&store, 3, &[]);
        let cancelled = AtomicBool::new(false);

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        let successor_staged = Arc::new(Barrier::new(2));
        let successor_from_block = Arc::clone(&successor_staged);
        let successor_from_link = Arc::clone(&successor_staged);
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            |job, handoffs| {
                if job.height == 3 {
                    successor_from_block.wait();
                }
                stub_block_stage(job, handoffs)
            },
            |job, _, _| {
                if job.height == 2 {
                    successor_from_link.wait();
                    return Err(retryable_message("prove selected Link", "injected failure"));
                }
                stub_link_stage(job)
            },
            |_, _| Ok(()),
        );

        assert_eq!(summary.promoted, 1, "height one still promotes");
        assert!(matches!(
            summary.stop,
            Some(PipelineStopRecord::Failed {
                identity: Some(identity),
                reason: SelectedHistoryWorkerBackoff::RetryableFailure {
                    phase: "prove selected Link",
                    ..
                },
                ..
            }) if identity.height == 2
        ));
        // Coverage stopped at the last verified height; every downstream
        // in-flight claim was released back to Pending.
        assert_eq!(
            store
                .get_selected_history_coverage()
                .unwrap()
                .map(|c| c.height),
            Some(1)
        );
        for height in [2u64, 3] {
            let job = store.get_recursive_proof_job(height).unwrap().unwrap();
            assert_eq!(
                job.state,
                RecursiveProofJobState::Pending,
                "height {height} must be re-claimable"
            );
            assert_eq!(job.attempt_counter, 1, "height {height} was in flight");
        }

        // A fresh poll re-claims from durable coverage and completes.
        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        assert_eq!(head.job.height, 2);
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            stub_block_stage,
            |job, _, _| stub_link_stage(job),
            |_, _| Ok(()),
        );
        assert!(summary.stop.is_none());
        assert_eq!(summary.promoted, 2);
        for height in [2u64, 3] {
            assert_eq!(
                store
                    .get_recursive_proof_job(height)
                    .unwrap()
                    .unwrap()
                    .attempt_counter,
                2
            );
        }
        assert_eq!(
            store
                .get_selected_history_coverage()
                .unwrap()
                .map(|c| (c.height, c.block_hash)),
            Some((3, chain[3].1))
        );
    }

    #[test]
    fn coverage_advance_mid_pipeline_discards_downstream_silently() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = enqueue_job_chain(&store, 2, &[]);
        let cancelled = AtomicBool::new(false);
        let hash_one = chain[1].1;

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        let store_for_verify = store.clone();
        let successor_staged = Arc::new(Barrier::new(2));
        let successor_from_block = Arc::clone(&successor_staged);
        let successor_from_verify = Arc::clone(&successor_staged);
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            |job, handoffs| {
                if job.height == 2 {
                    successor_from_block.wait();
                }
                stub_block_stage(job, handoffs)
            },
            |job, _, _| stub_link_stage(job),
            move |job, _| {
                if job.height == 1 {
                    successor_from_verify.wait();
                    // Simulate an external coverage advance (e.g. a verified
                    // terminal import) racing the pipeline's own promote.
                    store_for_verify
                        .complete_recursive_proof_job_and_promote_selected_history(
                            1,
                            hash_one,
                            &fake_terminal_package_bytes(1, hash_one),
                            &SelectedHistoryLadderUpdate::empty(genesis_header().log_slots),
                        )
                        .unwrap();
                }
                Ok(())
            },
        );

        assert_eq!(summary.promoted, 0, "the pipeline's own promote lost");
        assert!(matches!(
            summary.stop,
            Some(PipelineStopRecord::Superseded { identity })
                if identity.height == 1 && identity.block_hash == hash_one
        ));
        assert_eq!(
            store
                .get_selected_history_coverage()
                .unwrap()
                .map(|c| c.height),
            Some(1)
        );
        // The in-flight successor was discarded silently and is re-claimable.
        let discarded = store.get_recursive_proof_job(2).unwrap().unwrap();
        assert_eq!(discarded.state, RecursiveProofJobState::Pending);
        assert_eq!(discarded.attempt_counter, 1, "successor was in flight");

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        assert_eq!(head.job.height, 2);
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            stub_block_stage,
            |job, _, _| stub_link_stage(job),
            |_, _| Ok(()),
        );
        assert!(summary.stop.is_none());
        assert_eq!(summary.promoted, 1);
        assert_eq!(
            store
                .get_recursive_proof_job(2)
                .unwrap()
                .unwrap()
                .attempt_counter,
            2
        );
        assert_eq!(
            store
                .get_selected_history_coverage()
                .unwrap()
                .map(|c| c.height),
            Some(2)
        );
    }

    #[test]
    fn pipeline_never_overlaps_across_a_height_gap() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        enqueue_job_chain(&store, 3, &[2]);
        let cancelled = AtomicBool::new(false);

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        assert_eq!(head.job.height, 1);
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            stub_block_stage,
            |job, in_pipeline, _| {
                assert!(
                    job.height == 1 || in_pipeline.is_none(),
                    "a gap must never chain on an unrelated in-memory package"
                );
                stub_link_stage(job)
            },
            |_, _| Ok(()),
        );

        // Height one promotes and the gap ends this drain before height three
        // is even claimed. A fresh drain may claim it as a new head, where
        // the strict durable predecessor loader remains the authority.
        assert_eq!(summary.promoted, 1);
        assert!(summary.stop.is_none(), "gap is a clean drain boundary");
        assert_eq!(
            store
                .get_selected_history_coverage()
                .unwrap()
                .map(|c| c.height),
            Some(1)
        );
        assert_eq!(
            store.get_recursive_proof_job(3).unwrap().unwrap().state,
            RecursiveProofJobState::Pending
        );
        let fresh_head = claim_next_pipeline_job(&store).unwrap().unwrap();
        assert_eq!(fresh_head.job.height, 3);
        drop(fresh_head);
    }

    #[test]
    fn cancellation_mid_pipeline_releases_every_in_flight_claim() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        enqueue_job_chain(&store, 3, &[]);
        let cancelled = AtomicBool::new(false);

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        let successor_staged = Arc::new(Barrier::new(2));
        let successor_from_block = Arc::clone(&successor_staged);
        let successor_from_link = Arc::clone(&successor_staged);
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            |job, handoffs| {
                if job.height == 3 {
                    successor_from_block.wait();
                }
                stub_block_stage(job, handoffs)
            },
            |job, _, _| {
                if job.height == 2 {
                    successor_from_link.wait();
                    cancelled.store(true, Ordering::Release);
                    return Err(SelectedHistoryWorkerBackoff::Cancelled);
                }
                stub_link_stage(job)
            },
            |_, _| Ok(()),
        );

        assert!(matches!(
            summary.stop.as_ref(),
            Some(PipelineStopRecord::Cancelled { .. })
        ));
        // Whatever was promoted before cancellation is durable; everything
        // else returned to Pending.
        for height in 1..=3u64 {
            let job = store.get_recursive_proof_job(height).unwrap().unwrap();
            assert!(
                matches!(
                    job.state,
                    RecursiveProofJobState::Pending | RecursiveProofJobState::Complete
                ),
                "no claim may remain Running after cancellation"
            );
            assert_eq!(job.attempt_counter, 1, "height {height} entered the drain");
        }
        assert!(
            retain_cross_session_local_replay_tail(
                summary.stop.as_ref(),
                summary.last_promoted,
                summary.tail_package,
            )
            .is_none(),
            "cancellation must destroy every process-local replay tail"
        );
    }

    #[test]
    fn depth_one_gates_before_claiming_the_successor() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        enqueue_job_chain(&store, 2, &[]);
        let cancelled = AtomicBool::new(false);
        let checked = AtomicUsize::new(0);
        let head = claim_next_pipeline_job(&store).unwrap().unwrap();

        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, in_flight_tiers| {
                if !in_flight_tiers.is_empty() {
                    let successor = store.get_recursive_proof_job(2).unwrap().unwrap();
                    assert_eq!(
                        successor.state,
                        RecursiveProofJobState::Pending,
                        "depth must be checked before Pending becomes Running"
                    );
                    checked.fetch_add(1, Ordering::Relaxed);
                }
                1
            },
            stub_block_stage,
            |job, _, _| stub_link_stage(job),
            |_, _| Ok(()),
        );

        assert!(summary.stop.is_none());
        assert_eq!(summary.promoted, 2);
        assert!(checked.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn one_session_keeps_the_three_stage_pipeline_fed_until_the_queue_ends() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        enqueue_job_chain(&store, 5, &[]);
        let cancelled = AtomicBool::new(false);

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            stub_block_stage,
            |job, _, _| stub_link_stage(job),
            |_, _| Ok(()),
        );
        assert!(summary.stop.is_none());
        assert_eq!(summary.promoted, 5);
        assert_eq!(
            summary.last_promoted.map(|identity| identity.height),
            Some(5)
        );
        for height in 1u64..=5 {
            let job = store.get_recursive_proof_job(height).unwrap().unwrap();
            assert_eq!(job.state, RecursiveProofJobState::Complete);
            assert_eq!(job.attempt_counter, 1);
        }
    }

    #[test]
    fn small_session_drains_before_claiming_a_b255_successor() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = enqueue_job_chain(&store, 2, &[2]);
        store
            .enqueue_recursive_proof_job(2, chain[2].1, RecursiveProofJobTier::B255)
            .unwrap();
        let cancelled = AtomicBool::new(false);

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        assert_eq!(head.job.tier, RecursiveProofJobTier::B8);
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            stub_block_stage,
            |job, _, _| stub_link_stage(job),
            |_, _| Ok(()),
        );
        assert!(summary.stop.is_none());
        assert_eq!(summary.promoted, 1);
        let successor = store.get_recursive_proof_job(2).unwrap().unwrap();
        assert_eq!(successor.tier, RecursiveProofJobTier::B255);
        assert_eq!(successor.state, RecursiveProofJobState::Pending);
        assert_eq!(
            successor.attempt_counter, 0,
            "B255 must be claimed only after a fresh exclusive admission"
        );
    }

    #[test]
    fn promoted_tail_is_consumed_by_the_next_session_head() {
        struct SessionReplay(u64);

        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = enqueue_job_chain(&store, 5, &[4]);
        store
            .enqueue_recursive_proof_job(4, chain[4].1, RecursiveProofJobTier::B255)
            .unwrap();
        let cancelled = AtomicBool::new(false);

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        let first = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            stub_block_stage,
            |job, previous: Option<InPipelinePackage<SessionReplay>>, _| {
                if job.height > 1 {
                    assert_eq!(
                        previous.expect("same-session replay").local_replay.0 + 1,
                        job.height
                    );
                }
                Ok(LinkStageResult {
                    payload: job.height,
                    encoded_package: Arc::new(fake_terminal_package_bytes(
                        job.height,
                        job.block_hash,
                    )),
                    local_replay: SessionReplay(job.height),
                })
            },
            |_, _| Ok(()),
        );
        assert!(first.stop.is_none());
        assert_eq!(first.last_promoted.map(|identity| identity.height), Some(3));
        let retained = retain_cross_session_local_replay_tail(
            first.stop.as_ref(),
            first.last_promoted,
            first.tail_package,
        )
        .expect("fully promoted tail is retained");
        assert_eq!(retained.local_replay.0, 3);

        let next_head = claim_next_pipeline_job(&store).unwrap().unwrap();
        assert_eq!(next_head.job.height, 4);
        let mut retained = take_cross_session_local_replay_tail(next_head.job, Some(retained));
        let cross_session_uses = AtomicUsize::new(0);
        let second = run_selected_history_pipeline(
            &store,
            &cancelled,
            next_head,
            &mut None,
            |_, _| 1,
            stub_block_stage,
            |job, in_lane, _| {
                let previous = in_lane
                    .or_else(|| retained.take())
                    .expect("next session head consumes retained replay");
                assert_eq!(previous.local_replay.0 + 1, job.height);
                cross_session_uses.fetch_add(1, Ordering::Relaxed);
                Ok(LinkStageResult {
                    payload: job.height,
                    encoded_package: Arc::new(fake_terminal_package_bytes(
                        job.height,
                        job.block_hash,
                    )),
                    local_replay: SessionReplay(job.height),
                })
            },
            |_, _| Ok(()),
        );
        assert!(second.stop.is_none());
        assert_eq!(second.promoted, 1);
        assert_eq!(cross_session_uses.load(Ordering::Relaxed), 1);

        let mut tail = second.tail_package.expect("second session tail");
        Arc::make_mut(&mut tail.encoded)[0] ^= 1;
        let retained = retain_cross_session_local_replay_tail(
            second.stop.as_ref(),
            second.last_promoted,
            Some(tail),
        )
        .expect("successful local promotion authorizes retention without a reread");
        let mut third_head = claim_next_pipeline_job(&store).unwrap().unwrap();
        assert_eq!(third_head.job.height, 5);
        assert!(
            take_cross_session_local_replay_tail(third_head.job, Some(retained)).is_some(),
            "the cheap identity gate defers exact-byte authority to the Stage-A snapshot"
        );
        third_head.release().unwrap();
    }

    #[test]
    fn pipeline_moves_each_local_replay_once_and_drops_the_tail() {
        struct LinearReplay {
            height: u64,
            drops: Arc<AtomicUsize>,
        }

        impl Drop for LinearReplay {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        enqueue_job_chain(&store, 3, &[]);
        let cancelled = AtomicBool::new(false);
        let local_uses = Arc::new(AtomicUsize::new(0));
        let replay_drops = Arc::new(AtomicUsize::new(0));
        let uses = Arc::clone(&local_uses);
        let drops = Arc::clone(&replay_drops);

        let head = claim_next_pipeline_job(&store).unwrap().unwrap();
        let summary = run_selected_history_pipeline(
            &store,
            &cancelled,
            head,
            &mut None,
            |_, _| 3,
            stub_block_stage,
            move |job, in_pipeline: Option<InPipelinePackage<LinearReplay>>, _| {
                if job.height == 1 {
                    assert!(
                        in_pipeline.is_none(),
                        "pipeline head has no local predecessor"
                    );
                } else {
                    let previous = in_pipeline.expect("non-head must consume one local replay");
                    assert_eq!(previous.height + 1, job.height);
                    assert_eq!(previous.local_replay.height + 1, job.height);
                    uses.fetch_add(1, Ordering::Relaxed);
                }
                Ok(LinkStageResult {
                    payload: job.height,
                    encoded_package: Arc::new(fake_terminal_package_bytes(
                        job.height,
                        job.block_hash,
                    )),
                    local_replay: LinearReplay {
                        height: job.height,
                        drops: Arc::clone(&drops),
                    },
                })
            },
            |_, _| Ok(()),
        );

        assert!(summary.stop.is_none());
        assert_eq!(summary.promoted, 3);
        assert_eq!(local_uses.load(Ordering::Relaxed), 2);
        assert_eq!(
            replay_drops.load(Ordering::Relaxed),
            2,
            "only consumed predecessor capsules drop before the tail is returned"
        );
        drop(summary.tail_package);
        assert_eq!(
            replay_drops.load(Ordering::Relaxed),
            3,
            "two consumed capsules and the unconsumed drain tail all drop exactly once"
        );
    }

    #[test]
    fn depth_policy_is_fixed_by_stage_topology() {
        use RecursiveProofJobTier::{B255, B32, B8};

        // B255 anywhere collapses to strictly sequential processing.
        assert_eq!(planned_pipeline_depth(B255, &[]), 1);
        assert_eq!(planned_pipeline_depth(B8, &[B255]), 1);
        assert_eq!(planned_pipeline_depth(B8, &[B8, B255]), 1);

        assert_eq!(planned_pipeline_depth(B8, &[]), PIPELINE_STANDARD_DEPTH);
        assert_eq!(planned_pipeline_depth(B8, &[B8]), PIPELINE_STANDARD_DEPTH);
        assert_eq!(planned_pipeline_depth(B32, &[B8]), PIPELINE_STANDARD_DEPTH);
    }

    #[test]
    fn stop_control_reports_the_reason_at_the_lowest_discard_height() {
        let control = PipelineControl::new();
        let height_three = SelectedHistoryJobIdentity {
            height: 3,
            block_hash: [3; 32],
        };
        let height_two = SelectedHistoryJobIdentity {
            height: 2,
            block_hash: [2; 32],
        };
        control.record(PipelineStopRecord::Failed {
            identity: Some(height_three),
            reason: retryable_message("stage A", "first observed"),
            release_error: None,
        });
        control.record(PipelineStopRecord::Failed {
            identity: Some(height_two),
            reason: retryable_message("stage B", "lower height observed later"),
            release_error: None,
        });

        assert!(control.discards(2));
        assert!(!control.discards(1));
        assert!(matches!(
            control.into_record(),
            Some(PipelineStopRecord::Failed {
                identity: Some(identity),
                reason: SelectedHistoryWorkerBackoff::RetryableFailure {
                    phase: "stage B",
                    ..
                },
                ..
            }) if identity == height_two
        ));
    }

    #[test]
    fn predecessor_accumulator_is_bound_to_local_parent_and_epoch_header() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let genesis = genesis_header();
        let genesis_hash = block_id(&genesis);
        store.put_header_only(&genesis, &genesis_hash).unwrap();

        let accumulator = genesis_accumulator();
        validate_start_accumulator(&store, &accumulator, &genesis).unwrap();
        let mut forged = accumulator;
        forged.state_root[0] ^= 1;
        assert!(matches!(
            validate_start_accumulator(&store, &forged, &genesis),
            Err(SelectedHistoryWorkerBackoff::RetryableFailure {
                phase: "validate predecessor accumulator boundary",
                ..
            })
        ));
    }

    #[test]
    fn worker_source_has_one_claim_and_no_large_clone_or_queue() {
        let source = include_str!("selected_history_worker.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            production
                .matches("claim_next_recursive_proof_job()")
                .count(),
            1,
            "all claims funnel through the single durable-claim callsite"
        );
        assert!(!production.contains("VecDeque"));
        assert!(production.contains("struct InPipelinePackage<TL>"));
        assert!(production.contains("local_replay: TL"));
        assert!(production.contains("local_replay_tail: Option<InPipelinePackage<"));
        assert!(production.contains("take_cross_session_local_replay_tail("));
        assert!(production.contains("retain_cross_session_local_replay_tail("));
        assert!(!production.contains("get_recursive_proof_job_result("));
        assert_eq!(
            production
                .matches("load_claimed_recursive_proof_job_inputs_with_expected_predecessor")
                .count(),
            1,
            "Stage A must authorize retained bytes inside its sole input snapshot"
        );
        assert!(production.contains("last_package\n            .take()"));
        assert!(production.contains("bind_decoded_predecessor(predecessor)"));
        assert!(
            production.contains("loaded_registry: Option<LoadedSelectedRecursiveClassRegistry>")
        );
        assert_eq!(
            production
                .matches(".load_pinned_registry(expected_registry_digest)")
                .count(),
            1,
            "eager and lazy paths must funnel through one pinned loader"
        );
        assert!(!production.contains("registry_store.load()"));
        let identity_view = production
            .split("pub fn preloaded_registry_artifact_identities")
            .nth(1)
            .and_then(|tail| tail.split("pub fn run_pipelined").next())
            .expect("preloaded registry identity view");
        assert!(identity_view.contains(".loaded_registry"));
        assert!(identity_view.contains("RegistryNotPreloaded"));
        assert!(!identity_view.contains("populate_registry_cache("));
        assert!(!identity_view.contains("load_pinned_registry("));
        for forbidden in [
            "block_bytes.clone()",
            "block_proof_bytes.clone()",
            "block_auth_sidecar_bytes.clone()",
            "previous_result.clone()",
            "encoded_package.clone()",
            "SelectedRecursiveBlockArtifacts {",
            "component_inputs.clone()",
            "component_proof.clone()",
            "envelope.clone()",
        ] {
            assert!(!production.contains(forbidden), "found {forbidden}");
        }
        assert_eq!(
            production
                .matches("SelectedRecursiveBlockJob::from_native_verified(artifacts)")
                .count(),
            1,
            "worker must transfer the sole native-verified seal"
        );

        let run_pipelined = production
            .split("pub fn run_pipelined")
            .nth(1)
            .expect("production worker run method");
        let reserve = run_pipelined
            .find("begin_selected_history_proof_session(selected_tier_from_storage(tier))")
            .expect("proof session admission");
        let registry_load = run_pipelined
            .find("populate_registry_cache(")
            .expect("pinned registry cache lookup");
        let load = run_pipelined
            .find("load_claimed_recursive_proof_job_inputs")
            .expect("single large input load");
        let durable_ladder = run_pipelined
            .find("load_selected_history_ladder_parent_state(")
            .expect("durable forward ladder loader");
        let pipelined_ladder = run_pipelined
            .find("load_selected_history_pipelined_parent_state(")
            .expect("in-memory forward ladder loader");
        assert!(reserve < registry_load && registry_load < load);
        assert!(load < durable_ladder && load < pipelined_ladder);
        assert_eq!(
            production
                .matches("load_selected_history_ladder_parent_state(")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("load_selected_history_pipelined_parent_state(")
                .count(),
            1
        );
        assert!(!production.contains("reconstruct_historical_exact_state"));
        // Exactly one lane promotes, and stage B/C never claim.
        assert_eq!(production.matches(".promote(").count(), 1);
    }

    #[test]
    fn transaction_fixture_uses_canonical_fixed_width() {
        let tx = transaction(1, true, 2, true, false);
        assert_eq!(tx.body.inputs.len(), TX_INPUTS);
    }
}
