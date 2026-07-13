// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Crash-resumable production worker for selected Block+Link history proofs.
//!
//! This module is deliberately synchronous: the prover-role node calls
//! [`SelectedHistoryProverWorker::run_once`] from its bounded blocking worker.
//! Ordinary validating nodes never construct this worker.  One invocation
//! claims at most one durable MDBX job and retains no in-memory work queue.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};

use noid_block::{FullAcceptedBlockBatchItem, reconstruct_selected_recursive_block_artifacts};
use noid_chain::block::Block;
use noid_chain::consensus::header::asert_anchor_height;
use noid_chain::consensus::params::{EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS, TX_EPOCH_BLOCKS};
use noid_chain::storage::{
    MdbxStore, RecursiveProofJob, RecursiveProofJobState, RecursiveProofJobTier,
    derive_touched_segment_ids, load_selected_history_ladder_parent_state,
};
use noid_chain::{BlockHeader, SelectedHistoryLadderUpdate, block_id};
use noid_miner::{
    LoadedSelectedRecursiveClassRegistry, LocalSelectedRecursiveClassRegistryStore,
    LocalSelectedRecursiveMatrixSource, SelectedHistoryProofSession, SelectedRecursiveBlockJob,
    SelectedRecursiveLinkJob, SelectedRecursiveLinkPredecessor, SelectedRecursiveProverError,
    SelectedRecursiveTier, begin_selected_history_proof_session, selected_recursive_tier,
};
use noid_recursive::acceptance::split_link::tip_block_accumulator_split;
use noid_recursive::{
    ChainAccumulator, RecursiveConsensusState, SelectedHistoryTerminalPackage,
    decode_selected_history_terminal_package, genesis_accumulator,
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
    /// The shared process memory envelope could not be acquired.
    MemoryPressure {
        required_mib: usize,
        available_mib: usize,
    },
    /// A bounded local input/artifact/cryptographic phase failed closed.
    RetryableFailure { phase: &'static str, detail: String },
    /// A proof backend assertion unwound through the production boundary.
    Panicked,
}

/// Result of exactly one non-queueing worker poll.
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

/// Prover-role owner of the compact registry source and sequential matrix
/// source.  It owns no proof queue, decoded class matrix, or chain state.
pub struct SelectedHistoryProverWorker {
    store: MdbxStore,
    registry_store: LocalSelectedRecursiveClassRegistryStore,
    expected_registry_digest: [u8; 32],
    matrix_source: LocalSelectedRecursiveMatrixSource,
}

impl SelectedHistoryProverWorker {
    pub fn new(
        store: MdbxStore,
        registry_store: LocalSelectedRecursiveClassRegistryStore,
        expected_registry_digest: [u8; 32],
        matrix_source: LocalSelectedRecursiveMatrixSource,
    ) -> Self {
        // Expanded VK tables are not a permanent node-RAM baseline. The
        // pinned registry is materialized only for a claimed job, after that
        // job owns the stronger 8 GiB proof admission.
        Self {
            store,
            registry_store,
            expected_registry_digest,
            matrix_source,
        }
    }

    /// Claim and process at most one selected recursive proof job.
    ///
    /// The parent state comes from the worker's own durable forward ladder
    /// cursor, never from the caller's chain state, so this poll takes no
    /// chain lock and is independent of how far the canonical tip has
    /// advanced past the proof pipeline. Cancellation is cooperative at
    /// explicit phase boundaries; an in-flight cryptographic backend call
    /// runs to its owning drop point instead of abandoning allocations
    /// halfway through a proof.
    pub fn run_once(&mut self, cancelled: &AtomicBool) -> SelectedHistoryWorkerOutcome {
        let Self {
            store,
            registry_store,
            expected_registry_digest,
            matrix_source,
        } = self;
        let PreparedSelectedHistoryClaim {
            mut running,
            identity,
            proof_session,
        } = match prepare_claim(store, cancelled) {
            Ok(prepared) => prepared,
            Err(outcome) => return outcome,
        };
        let claimed = running.job;

        let processed = catch_unwind(AssertUnwindSafe(|| {
            process_claimed_job(
                store,
                registry_store,
                *expected_registry_digest,
                matrix_source,
                claimed,
                proof_session,
                cancelled,
            )
        }));

        let candidate = match processed {
            Ok(Ok(candidate)) => candidate,
            Ok(Err(reason)) => return release_backoff(&mut running, identity, reason),
            Err(_) => {
                return release_backoff(
                    &mut running,
                    identity,
                    SelectedHistoryWorkerBackoff::Panicked,
                );
            }
        };

        if cancelled.load(Ordering::Acquire) {
            return release_backoff(
                &mut running,
                identity,
                SelectedHistoryWorkerBackoff::Cancelled,
            );
        }
        if candidate.height != identity.height || candidate.block_hash != identity.block_hash {
            return release_backoff(
                &mut running,
                identity,
                retryable_message(
                    "promote selected terminal",
                    "verified package identity changed before promotion",
                ),
            );
        }

        match running.promote(&candidate.encoded_package, &candidate.ladder_update) {
            Ok(()) => SelectedHistoryWorkerOutcome::Completed(identity),
            Err(error) => release_backoff(
                &mut running,
                identity,
                retryable("atomically promote selected terminal", error),
            ),
        }
    }
}

struct PreparedSelectedHistoryClaim<'a, S> {
    running: RunningJobGuard<'a>,
    identity: SelectedHistoryJobIdentity,
    proof_session: S,
}

fn prepare_claim<'a>(
    store: &'a MdbxStore,
    cancelled: &AtomicBool,
) -> Result<
    PreparedSelectedHistoryClaim<'a, SelectedHistoryProofSession>,
    SelectedHistoryWorkerOutcome,
> {
    prepare_claim_with_admission(store, cancelled, || {
        begin_selected_history_proof_session().map_err(map_prover_admission)
    })
}

fn prepare_claim_with_admission<'a, A, S>(
    store: &'a MdbxStore,
    cancelled: &AtomicBool,
    admission: A,
) -> Result<PreparedSelectedHistoryClaim<'a, S>, SelectedHistoryWorkerOutcome>
where
    A: FnOnce() -> Result<S, SelectedHistoryWorkerBackoff>,
{
    if cancelled.load(Ordering::Acquire) {
        return Err(backoff(None, SelectedHistoryWorkerBackoff::Cancelled, None));
    }

    // Exactly one durable claim per poll. MDBX chooses the numerically lowest
    // canonical Pending job without materializing a queue.
    let claimed = match store.claim_next_recursive_proof_job() {
        Ok(Some(job)) => job,
        Ok(None) => {
            return Err(backoff(None, SelectedHistoryWorkerBackoff::Idle, None));
        }
        Err(error) => {
            return Err(backoff(None, retryable("claim durable job", error), None));
        }
    };
    let mut running = RunningJobGuard::new(store, claimed);
    let identity = SelectedHistoryJobIdentity::from(claimed);

    if cancelled.load(Ordering::Acquire) {
        return Err(release_backoff(
            &mut running,
            identity,
            SelectedHistoryWorkerBackoff::Cancelled,
        ));
    }

    // Reserve the complete m24 envelope before any job input is loaded.
    // Admission failure therefore adds no state allocation to an already
    // memory-pressured process.
    let proof_session = match catch_unwind(AssertUnwindSafe(admission)) {
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

    Ok(PreparedSelectedHistoryClaim {
        running,
        identity,
        proof_session,
    })
}

struct CompletionCandidate {
    height: u64,
    block_hash: [u8; 32],
    encoded_package: Vec<u8>,
    /// The proven block's end-state boundary, persisted atomically with the
    /// promotion so the forward ladder cursor can never lag coverage.
    ladder_update: SelectedHistoryLadderUpdate,
}

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
}

impl<'a> RunningJobGuard<'a> {
    fn new(store: &'a MdbxStore, job: RecursiveProofJob) -> Self {
        let armed = job.state == RecursiveProofJobState::Running;
        Self { store, job, armed }
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
            let _ = self
                .store
                .release_recursive_proof_job(self.job.height, self.job.block_hash);
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

fn process_claimed_job(
    store: &MdbxStore,
    registry_store: &LocalSelectedRecursiveClassRegistryStore,
    expected_registry_digest: [u8; 32],
    matrix_source: &mut LocalSelectedRecursiveMatrixSource,
    claimed: RecursiveProofJob,
    mut proof_session: SelectedHistoryProofSession,
    cancelled: &AtomicBool,
) -> Result<CompletionCandidate, SelectedHistoryWorkerBackoff> {
    check_cancelled(cancelled)?;

    // Registry expansion is transient and happens only inside the stronger
    // 8 GiB selected-history proof admission already owned by this job.
    let loaded_registry = registry_store
        .load_pinned(expected_registry_digest)
        .map_err(|error| retryable("load pinned selected-history registry", error))?;

    let block_classes = loaded_registry
        .block_classes()
        .map_err(|error| retryable("validate Block class registry", error))?;
    let link_classes = loaded_registry
        .link_classes()
        .map_err(|error| retryable("validate Link class registry", error))?;
    check_cancelled(cancelled)?;

    let inputs = store
        .load_claimed_recursive_proof_job_inputs(claimed)
        .map_err(|error| retryable("load one claimed MDBX snapshot", error))?;
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
    let (start_accumulator, predecessor) = predecessor_from_result(
        &loaded_registry,
        job.height,
        &parent_header,
        previous_result,
    )?;
    validate_start_accumulator(store, &start_accumulator, &parent_header)?;
    check_cancelled(cancelled)?;

    // This is the sole raw-state load. The worker's durable forward ladder
    // cursor supplies the exact parent state with columns resident only for
    // the sorted touched set, independent of the canonical tip's undo window.
    let start_state =
        load_selected_history_ladder_parent_state(store, &parent_header, &required_segment_ids)
            .map_err(|error| retryable("load forward ladder parent state", error))?;
    check_cancelled(cancelled)?;

    let (artifacts, ladder_update) = reconstruct_selected_recursive_block_artifacts(
        start_consensus,
        start_accumulator,
        parent_header,
        start_state,
        FullAcceptedBlockBatchItem {
            block,
            block_proof_bytes,
            block_auth_sidecar_bytes,
        },
    )
    .map_err(|error| retryable("reconstruct selected Block artifacts", error))?;
    check_cancelled(cancelled)?;
    // Keep only the fixed ten-lane terminal identity. The consuming job moves
    // every B255-sized component/proof vector into Block construction.
    let expected_end_accumulator = artifacts.end_accumulator().clone();

    let current_block = proof_session
        .prove_block(
            &block_classes,
            SelectedRecursiveBlockJob::from_native_verified(artifacts),
        )
        .map_err(|error| retryable("prove selected Block", error))?;

    // The consuming Block job drops its B255-sized retained carrier before
    // Link proving; only the standalone Block envelope crosses this boundary.
    check_cancelled(cancelled)?;

    let linked = proof_session
        .prove_link(
            &link_classes,
            SelectedRecursiveLinkJob {
                predecessor,
                current_block,
            },
            matrix_source,
        )
        .map_err(|error| retryable("prove selected Link", error))?;
    check_cancelled(cancelled)?;

    let tip_slot = selected_tier_slot(linked.tier);
    let package =
        SelectedHistoryTerminalPackage::new(job.height, job.block_hash, tip_slot, linked.envelope)
            .map_err(|error| retryable("construct selected terminal package", error))?;
    let encoded_package = package
        .encode()
        .map_err(|error| retryable("encode selected terminal package", error))?;

    // Prepare the two small local authorities while proof admission is still
    // held, minimizing (without eliminating) the handoff window in which a
    // native miner could acquire the process-global ledger first.
    let epoch_height = (block_header.height / TX_EPOCH_BLOCKS) * TX_EPOCH_BLOCKS;
    let epoch_anchor_header = store
        .get_header(epoch_height)
        .map_err(|error| retryable("read terminal epoch anchor", error))?
        .ok_or_else(|| {
            retryable_message(
                "read terminal epoch anchor",
                "canonical epoch-anchor header is missing",
            )
        })?;
    let terminal_registry = loaded_registry.terminal_registry();

    // All proof artifacts and transient resident CSR matrices are gone here,
    // but retain the stronger 8 GiB admission through streaming verification.
    // This covers the expanded registry without a permanent node-RAM baseline
    // and avoids an ungoverned handoff between two independent reservations.
    check_cancelled(cancelled)?;

    let verified_accumulator = noid_recursive::verify_selected_history_terminal(
        &package,
        &terminal_registry,
        &block_header,
        &epoch_anchor_header,
        matrix_source,
    )
    .map_err(|error| retryable("stream-verify selected terminal", error))?;
    drop(proof_session);
    if verified_accumulator != expected_end_accumulator {
        return Err(retryable_message(
            "validate terminal accumulator",
            "streaming verifier result differs from accepted Block reconstruction",
        ));
    }
    check_cancelled(cancelled)?;

    Ok(CompletionCandidate {
        height: job.height,
        block_hash: job.block_hash,
        encoded_package,
        ladder_update,
    })
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
    let package = decode_selected_history_terminal_package(&previous_result.bytes)
        .map_err(|error| retryable("decode recursive predecessor", error))?;
    drop(previous_result.bytes);
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
        SelectedRecursiveProverError::MemoryPressure {
            required_mib,
            available_mib,
        } => SelectedHistoryWorkerBackoff::MemoryPressure {
            required_mib,
            available_mib,
        },
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
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{TX_INPUTS, Transaction, TxBody, TxInput, TxOutput, output_bitmap_bit};
    use std::sync::atomic::AtomicUsize;

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

    fn enqueue_height_one_job(store: &MdbxStore) -> RecursiveProofJob {
        let genesis = genesis_header();
        let mut header = genesis;
        header.height = 1;
        header.prev_block_hash = block_id(&genesis);
        header.timestamp = header.timestamp.saturating_add(1);
        header.nonce = 0x5151;
        let hash = block_id(&header);
        store.put_header_only(&header, &hash).unwrap();
        store
            .enqueue_recursive_proof_job(1, hash, RecursiveProofJobTier::B8)
            .unwrap();
        store.get_recursive_proof_job(1).unwrap().unwrap()
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

            let outcome = prepare_claim_with_admission(&store, &cancelled, || {
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
    fn cancellation_after_admission_releases_claim() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let queued = enqueue_height_one_job(&store);
        let cancelled = AtomicBool::new(false);

        let outcome = prepare_claim_with_admission(&store, &cancelled, || {
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
            1
        );
        assert!(!production.contains("VecDeque"));
        assert!(production.contains(".load_pinned(expected_registry_digest)"));
        assert!(!production.contains("registry_store.load()"));
        assert!(!production.contains("registry: LoadedSelectedRecursiveClassRegistry"));
        for forbidden in [
            "block_bytes.clone()",
            "block_proof_bytes.clone()",
            "block_auth_sidecar_bytes.clone()",
            "previous_result.clone()",
            "SelectedRecursiveBlockArtifacts {",
            "component_inputs.clone()",
            "component_proof.clone()",
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

        let reserve = production
            .find("begin_selected_history_proof_session()")
            .expect("proof session admission");
        let load = production
            .find("load_claimed_recursive_proof_job_inputs(claimed)")
            .expect("single large input load");
        let registry_load = production
            .find(".load_pinned(expected_registry_digest)")
            .expect("transient pinned registry load");
        let ladder_load = production
            .find("load_selected_history_ladder_parent_state(")
            .expect("forward ladder parent state load");
        assert!(reserve < registry_load && registry_load < load && load < ladder_load);
        assert_eq!(
            production
                .matches("load_selected_history_ladder_parent_state(")
                .count(),
            1
        );
        assert!(
            !production.contains("reconstruct_historical_exact_state"),
            "the worker must never roll back from the canonical tip"
        );
    }

    #[test]
    fn transaction_fixture_uses_canonical_fixed_width() {
        let tx = transaction(1, true, 2, true, false);
        assert_eq!(tx.body.inputs.len(), TX_INPUTS);
    }
}
