// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact-object scheduling with source rotation and progress preservation.

use std::collections::{HashMap, HashSet};

use libp2p::PeerId;
use thiserror::Error;

use super::types::{FailureDomain, ObjectClaimId, ObjectId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchAssignment {
    pub peer: PeerId,
    pub object: ObjectId,
    pub resumed_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchState {
    Wanted,
    InFlight {
        primary: PeerId,
        hedge: Option<PeerId>,
    },
    Received {
        source: PeerId,
        object: ObjectId,
    },
    Verified {
        object: ObjectId,
    },
}

#[derive(Clone, Copy, Debug)]
struct Source {
    object: ObjectId,
    failure_domain: FailureDomain,
    failures: u32,
    /// A remote `Busy` response is transport backpressure, not evidence that
    /// the advertised immutable object disappeared. Keep the source, but do
    /// not immediately recreate a synchronized retry wave against it.
    retry_after_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct SourceHistory {
    failures: u32,
    retry_after_ms: u64,
}

const SOURCE_FAILURE_BACKOFF_BASE_MS: u64 = 1_000;
const SOURCE_FAILURE_BACKOFF_MAX_MS: u64 = 60_000;
/// A source that repeatedly fails an actual transport request is exhausted for
/// the current immutable plan.  A fresh plan may admit it again; `Busy` and
/// local queue pressure never consume this budget.
const SOURCE_TRANSPORT_FAILURE_LIMIT: u32 = 3;

#[derive(Debug)]
struct FetchJob {
    state: FetchState,
    sources: HashMap<PeerId, Source>,
    /// Transport history survives a disconnect/reconnect of the same peer.
    /// Otherwise a flapping connection can repeatedly resurrect itself as a
    /// "new" provider, reset the plan watchdog and avoid the bounded failure
    /// budget forever.
    source_history: HashMap<PeerId, SourceHistory>,
    seen_sources: HashSet<PeerId>,
    /// A response may already be decoded in another event lane when its
    /// disconnect overtakes it. Keep only the exact correlations that were
    /// in flight at transport loss so those locally queued bytes can still be
    /// accepted while normal failover proceeds.
    late_responses: HashMap<PeerId, ObjectId>,
    /// Providers that explicitly lacked or failed authentication for this
    /// exact claim during the current immutable plan. A repeated inventory
    /// announcement must not silently resurrect the same bad source.
    unavailable_sources: HashSet<PeerId>,
    selected_object: Option<ObjectId>,
    partial_bytes: u32,
    last_progress_ms: Option<u64>,
}

impl FetchJob {
    fn new() -> Self {
        Self {
            state: FetchState::Wanted,
            sources: HashMap::new(),
            source_history: HashMap::new(),
            seen_sources: HashSet::new(),
            late_responses: HashMap::new(),
            unavailable_sources: HashSet::new(),
            selected_object: None,
            partial_bytes: 0,
            last_progress_ms: None,
        }
    }

    fn active_source(&self, peer: PeerId) -> bool {
        match self.state {
            FetchState::InFlight { primary, hedge } => peer == primary || hedge == Some(peer),
            FetchState::Received { source, .. } => peer == source,
            FetchState::Wanted | FetchState::Verified { .. } => false,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FetchError {
    #[error("the object claim is not part of the active fetch set")]
    UnknownClaim,
    #[error("the advertised object does not satisfy the requested claim")]
    ClaimMismatch,
    #[error("the object has no eligible source")]
    NoSource,
    #[error("the fetch job is not in the required state")]
    InvalidState,
    #[error("the peer is not an active source for this object")]
    InactiveSource,
    #[error("reported progress moved backwards or exceeded the object length")]
    InvalidProgress,
    #[error("the received object differs from the exact assigned object")]
    ObjectMismatch,
}

/// Mutable transport state for immutable object claims.
///
/// Failure is scoped to one `(claim, source)` lease. It never removes another
/// job and never changes the `SyncPlan` that created the claims.
#[derive(Default)]
pub struct ObjectFetcher {
    jobs: HashMap<ObjectClaimId, FetchJob>,
}

impl ObjectFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn want(&mut self, claim: ObjectClaimId) -> bool {
        if self.jobs.contains_key(&claim) {
            return false;
        }
        self.jobs.insert(claim, FetchJob::new());
        true
    }

    pub fn advertise(
        &mut self,
        claim: ObjectClaimId,
        peer: PeerId,
        failure_domain: FailureDomain,
        object: ObjectId,
    ) -> Result<(), FetchError> {
        self.advertise_new(claim, peer, failure_domain, object)
            .map(|_| ())
    }

    /// Advertise one exact source and report whether it added a genuinely new
    /// eligible `(claim, peer)` lease. Duplicate inventories are harmless but
    /// must not be mistaken for transfer progress by plan-level watchdogs.
    pub fn advertise_new(
        &mut self,
        claim: ObjectClaimId,
        peer: PeerId,
        failure_domain: FailureDomain,
        object: ObjectId,
    ) -> Result<bool, FetchError> {
        if object.claim() != claim {
            return Err(FetchError::ClaimMismatch);
        }
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        if job.unavailable_sources.contains(&peer) {
            return Ok(false);
        }
        let previous = job.sources.get(&peer).copied();
        let history = job.source_history.entry(peer).or_default();
        let newly_discovered = job.seen_sources.insert(peer);
        job.sources.insert(
            peer,
            Source {
                object,
                failure_domain,
                failures: previous.map_or(history.failures, |source| source.failures),
                retry_after_ms: previous
                    .map_or(history.retry_after_ms, |source| source.retry_after_ms),
            },
        );
        Ok(newly_discovered)
    }

    pub fn start_primary(
        &mut self,
        claim: ObjectClaimId,
        now_ms: u64,
    ) -> Result<FetchAssignment, FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        if job.state != FetchState::Wanted {
            return Err(FetchError::InvalidState);
        }

        let selected = choose_source(job, None, now_ms).ok_or(FetchError::NoSource)?;
        let source = job.sources[&selected];
        job.selected_object = Some(source.object);
        job.state = FetchState::InFlight {
            primary: selected,
            hedge: None,
        };
        job.last_progress_ms = Some(now_ms);
        Ok(FetchAssignment {
            peer: selected,
            object: source.object,
            resumed_bytes: job.partial_bytes,
        })
    }

    /// Add at most one hedge after the primary stopped making progress.
    /// The hedge must advertise the exact same object and come from a distinct
    /// failure domain.
    pub fn start_hedge(
        &mut self,
        claim: ObjectClaimId,
        now_ms: u64,
        no_progress_for_ms: u64,
    ) -> Result<FetchAssignment, FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        let (primary, hedge) = match job.state {
            FetchState::InFlight { primary, hedge } => (primary, hedge),
            _ => return Err(FetchError::InvalidState),
        };
        if hedge.is_some()
            || now_ms.saturating_sub(job.last_progress_ms.unwrap_or(now_ms)) < no_progress_for_ms
        {
            return Err(FetchError::InvalidState);
        }
        let primary_source = job.sources.get(&primary).ok_or(FetchError::NoSource)?;
        let selected = choose_source(job, Some((primary, primary_source.failure_domain)), now_ms)
            .ok_or(FetchError::NoSource)?;
        let source = job.sources[&selected];
        job.state = FetchState::InFlight {
            primary,
            hedge: Some(selected),
        };
        Ok(FetchAssignment {
            peer: selected,
            object: source.object,
            resumed_bytes: job.partial_bytes,
        })
    }

    pub fn record_progress(
        &mut self,
        claim: ObjectClaimId,
        peer: PeerId,
        received_bytes: u32,
        now_ms: u64,
    ) -> Result<(), FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        if !job.active_source(peer) {
            return Err(FetchError::InactiveSource);
        }
        let object = job.selected_object.ok_or(FetchError::InvalidState)?;
        if received_bytes < job.partial_bytes
            || object
                .encoded_len()
                .is_some_and(|encoded_len| received_bytes > encoded_len)
        {
            return Err(FetchError::InvalidProgress);
        }
        job.partial_bytes = received_bytes;
        job.last_progress_ms = Some(now_ms);
        if let Some(source) = job.sources.get_mut(&peer) {
            source.failures = 0;
            source.retry_after_ms = 0;
        }
        job.source_history.insert(peer, SourceHistory::default());
        Ok(())
    }

    pub fn finish_receive(
        &mut self,
        claim: ObjectClaimId,
        peer: PeerId,
        object: ObjectId,
    ) -> Result<(), FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        let active = job.active_source(peer);
        let late = job.late_responses.get(&peer).copied() == Some(object)
            && matches!(job.state, FetchState::Wanted | FetchState::InFlight { .. });
        if !active && !late {
            return Err(FetchError::InactiveSource);
        }
        if object.claim() != claim || job.selected_object != Some(object) {
            return Err(FetchError::ObjectMismatch);
        }
        job.partial_bytes = object.encoded_len().unwrap_or(job.partial_bytes);
        if let Some(source) = job.sources.get_mut(&peer) {
            source.failures = 0;
            source.retry_after_ms = 0;
        }
        job.source_history.insert(peer, SourceHistory::default());
        job.late_responses.clear();
        job.state = FetchState::Received {
            source: peer,
            object,
        };
        Ok(())
    }

    pub fn mark_verified(
        &mut self,
        claim: ObjectClaimId,
        object: ObjectId,
    ) -> Result<(), FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        if !matches!(job.state, FetchState::Received { object: received, .. } if received == object)
        {
            return Err(FetchError::InvalidState);
        }
        job.late_responses.clear();
        job.state = FetchState::Verified { object };
        Ok(())
    }

    /// Fail one source lease. Verified objects and all unrelated jobs survive.
    pub fn fail_source_at(
        &mut self,
        claim: ObjectClaimId,
        peer: PeerId,
        now_ms: u64,
    ) -> Result<(), FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        let exhausted = if let Some(source) = job.sources.get_mut(&peer) {
            source.failures = source.failures.saturating_add(1);
            let shift = source.failures.saturating_sub(1).min(16);
            let delay = SOURCE_FAILURE_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(SOURCE_FAILURE_BACKOFF_MAX_MS);
            source.retry_after_ms = source.retry_after_ms.max(now_ms.saturating_add(delay));
            job.source_history.insert(
                peer,
                SourceHistory {
                    failures: source.failures,
                    retry_after_ms: source.retry_after_ms,
                },
            );
            source.failures >= SOURCE_TRANSPORT_FAILURE_LIMIT
        } else {
            false
        };
        job.state = match job.state {
            FetchState::InFlight {
                primary,
                hedge: Some(hedge),
            } if primary == peer => FetchState::InFlight {
                primary: hedge,
                hedge: None,
            },
            FetchState::InFlight { primary, hedge } if hedge == Some(peer) => {
                FetchState::InFlight {
                    primary,
                    hedge: None,
                }
            }
            FetchState::InFlight { primary, .. } if primary == peer => FetchState::Wanted,
            // Complete bytes are locally owned. A later transport event cannot
            // revoke the verifier's authority over them.
            FetchState::Received { .. } => job.state,
            state => state,
        };
        if exhausted && !matches!(job.state, FetchState::Received { source, .. } if source == peer)
        {
            job.late_responses.remove(&peer);
            job.sources.remove(&peer);
            job.unavailable_sources.insert(peer);
            if job.state == FetchState::Wanted
                && job.selected_object.is_some_and(|selected| {
                    !job.sources.values().any(|source| source.object == selected)
                })
            {
                job.selected_object = None;
                job.partial_bytes = 0;
                job.last_progress_ms = None;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn fail_source(&mut self, claim: ObjectClaimId, peer: PeerId) -> Result<(), FetchError> {
        self.fail_source_at(claim, peer, 0)
    }

    /// Return a locally scheduled assignment to `Wanted` without penalizing
    /// its source. This is used when the bounded transport queue is full
    /// before the request reaches the swarm: no network failure occurred and
    /// the exact object/source advertisement remains valid.
    pub fn defer_source(&mut self, claim: ObjectClaimId, peer: PeerId) -> Result<(), FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        job.state = match job.state {
            FetchState::InFlight {
                primary,
                hedge: Some(hedge),
            } if primary == peer => FetchState::InFlight {
                primary: hedge,
                hedge: None,
            },
            FetchState::InFlight { primary, hedge } if hedge == Some(peer) => {
                FetchState::InFlight {
                    primary,
                    hedge: None,
                }
            }
            FetchState::InFlight { primary, .. } if primary == peer => FetchState::Wanted,
            state => state,
        };
        Ok(())
    }

    /// Return an exact request to `Wanted` after the remote server explicitly
    /// reported bounded data-plane pressure. Unlike `fail_source`, this does
    /// not penalize or remove the provider. The immutable object selection and
    /// all verified progress remain unchanged.
    pub fn busy_source(
        &mut self,
        claim: ObjectClaimId,
        peer: PeerId,
        retry_at_ms: u64,
    ) -> Result<(), FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        let source = job.sources.get_mut(&peer).ok_or(FetchError::NoSource)?;
        source.retry_after_ms = source.retry_after_ms.max(retry_at_ms);
        job.source_history.insert(
            peer,
            SourceHistory {
                failures: source.failures,
                retry_after_ms: source.retry_after_ms,
            },
        );
        job.state = match job.state {
            FetchState::InFlight {
                primary,
                hedge: Some(hedge),
            } if primary == peer => FetchState::InFlight {
                primary: hedge,
                hedge: None,
            },
            FetchState::InFlight { primary, hedge } if hedge == Some(peer) => {
                FetchState::InFlight {
                    primary,
                    hedge: None,
                }
            }
            FetchState::InFlight { primary, .. } if primary == peer => FetchState::Wanted,
            FetchState::Received { source, .. } if source == peer => FetchState::Wanted,
            state => state,
        };
        Ok(())
    }

    /// The peer explicitly reported that it does not have this exact byte
    /// encoding. Unlike a transport timeout, retrying the same source cannot
    /// make progress, so remove only this advertisement. The semantic claim
    /// and every other source/job remain intact.
    pub fn mark_unavailable(
        &mut self,
        claim: ObjectClaimId,
        peer: PeerId,
    ) -> Result<(), FetchError> {
        self.fail_source_at(claim, peer, 0)?;
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        job.late_responses.remove(&peer);
        job.sources.remove(&peer);
        job.unavailable_sources.insert(peer);
        if job.state == FetchState::Wanted
            && job.selected_object.is_some_and(|selected| {
                !job.sources.values().any(|source| source.object == selected)
            })
        {
            job.selected_object = None;
            job.partial_bytes = 0;
            job.last_progress_ms = None;
        }
        Ok(())
    }

    /// Reject bytes that have already crossed the transport boundary but
    /// failed their authenticated object check. Unlike a disconnect or
    /// timeout, this explicitly revokes the matching locally-owned Received
    /// state so an alternate source can be scheduled.
    pub fn reject_source_object(
        &mut self,
        claim: ObjectClaimId,
        peer: PeerId,
    ) -> Result<(), FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        let known = job.sources.contains_key(&peer)
            || job.active_source(peer)
            || matches!(job.state, FetchState::Received { source, .. } if source == peer);
        if !known {
            return Err(FetchError::NoSource);
        }
        job.state = match job.state {
            FetchState::InFlight {
                primary,
                hedge: Some(hedge),
            } if primary == peer => FetchState::InFlight {
                primary: hedge,
                hedge: None,
            },
            FetchState::InFlight { primary, hedge } if hedge == Some(peer) => {
                FetchState::InFlight {
                    primary,
                    hedge: None,
                }
            }
            FetchState::InFlight { primary, .. } if primary == peer => FetchState::Wanted,
            FetchState::Received { source, .. } if source == peer => FetchState::Wanted,
            state => state,
        };
        job.late_responses.remove(&peer);
        job.sources.remove(&peer);
        job.unavailable_sources.insert(peer);
        if job.state == FetchState::Wanted
            && job.selected_object.is_some_and(|selected| {
                !job.sources.values().any(|source| source.object == selected)
            })
        {
            job.selected_object = None;
            job.partial_bytes = 0;
            job.last_progress_ms = None;
        }
        Ok(())
    }

    /// Quarantine one provider for every object in this immutable plan after
    /// it has supplied bytes that fail an exact authenticated check. This is
    /// deliberately stronger than a timeout or an explicit per-object
    /// `unavailable` response. Already received bytes remain locally owned and
    /// are still judged by their independent verifier; verified progress is
    /// never revoked.
    pub fn quarantine_source(&mut self, peer: PeerId) {
        for job in self.jobs.values_mut() {
            job.state = match job.state {
                FetchState::InFlight {
                    primary,
                    hedge: Some(hedge),
                } if primary == peer => FetchState::InFlight {
                    primary: hedge,
                    hedge: None,
                },
                FetchState::InFlight { primary, hedge } if hedge == Some(peer) => {
                    FetchState::InFlight {
                        primary,
                        hedge: None,
                    }
                }
                FetchState::InFlight { primary, .. } if primary == peer => FetchState::Wanted,
                state => state,
            };
            job.late_responses.remove(&peer);
            job.sources.remove(&peer);
            job.unavailable_sources.insert(peer);
            if job.state == FetchState::Wanted
                && job.selected_object.is_some_and(|selected| {
                    !job.sources.values().any(|source| source.object == selected)
                })
            {
                job.selected_object = None;
                job.partial_bytes = 0;
                job.last_progress_ms = None;
            }
        }
    }

    /// Drop a dead transport source everywhere without discarding any job.
    pub fn disconnect(&mut self, peer: PeerId) {
        for job in self.jobs.values_mut() {
            if matches!(job.state, FetchState::InFlight { primary, hedge } if primary == peer || hedge == Some(peer))
            {
                if let Some(object) = job.selected_object {
                    job.late_responses.insert(peer, object);
                }
            }
            let _ = match job.state {
                FetchState::InFlight {
                    primary,
                    hedge: Some(hedge),
                } if primary == peer => {
                    job.state = FetchState::InFlight {
                        primary: hedge,
                        hedge: None,
                    };
                    Some(())
                }
                FetchState::InFlight { primary, hedge } if hedge == Some(peer) => {
                    job.state = FetchState::InFlight {
                        primary,
                        hedge: None,
                    };
                    Some(())
                }
                FetchState::InFlight { primary, .. } if primary == peer => {
                    job.state = FetchState::Wanted;
                    Some(())
                }
                // Once the complete bytes have crossed the transport
                // boundary they are locally owned.  Disconnecting their
                // source while disk/root verification is running must not
                // turn the exact job back into network work or invalidate the
                // worker's eventual Verified capability.
                FetchState::Received { .. } => None,
                _ => None,
            };
            job.sources.remove(&peer);
        }
    }

    /// Forget one disconnected request correlation after its bounded
    /// transport/event grace elapsed without a response.
    pub fn forget_late_response(&mut self, claim: ObjectClaimId, peer: PeerId, object: ObjectId) {
        let Some(job) = self.jobs.get_mut(&claim) else {
            return;
        };
        if job.late_responses.get(&peer).copied() == Some(object) {
            job.late_responses.remove(&peer);
        }
        if job.state == FetchState::Wanted
            && job.late_responses.is_empty()
            && job.selected_object.is_some_and(|selected| {
                !job.sources.values().any(|source| source.object == selected)
            })
        {
            job.selected_object = None;
            job.partial_bytes = 0;
            job.last_progress_ms = None;
        }
    }

    /// When every provider for a pinned byte digest has disappeared, allow a
    /// clean restart from another encoding of the same semantic claim. Partial
    /// bytes are deliberately discarded; other jobs remain untouched.
    pub fn release_unavailable_encoding(
        &mut self,
        claim: ObjectClaimId,
    ) -> Result<bool, FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        if job.state != FetchState::Wanted {
            return Err(FetchError::InvalidState);
        }
        let Some(selected) = job.selected_object else {
            return Ok(false);
        };
        if job.sources.values().any(|source| source.object == selected) {
            return Ok(false);
        }
        job.selected_object = None;
        job.partial_bytes = 0;
        job.last_progress_ms = None;
        Ok(true)
    }

    pub fn state(&self, claim: ObjectClaimId) -> Option<FetchState> {
        self.jobs.get(&claim).map(|job| job.state)
    }

    pub fn partial_bytes(&self, claim: ObjectClaimId) -> Option<u32> {
        self.jobs.get(&claim).map(|job| job.partial_bytes)
    }

    pub fn counts(&self) -> FetchCounts {
        let mut counts = FetchCounts::default();
        for job in self.jobs.values() {
            match job.state {
                FetchState::Wanted => counts.wanted += 1,
                FetchState::InFlight { .. } => counts.in_flight += 1,
                FetchState::Received { .. } => counts.received += 1,
                FetchState::Verified { .. } => counts.verified += 1,
            }
        }
        counts
    }

    /// True when every unfinished job is currently parked. This may be only a
    /// temporary backoff or `Busy` interval and therefore is sufficient to
    /// trigger provider discovery, but never sufficient to retire a plan.
    pub fn unfinished_transport_is_stalled(&self, now_ms: u64) -> bool {
        let mut unfinished = false;
        for job in self.jobs.values() {
            if matches!(job.state, FetchState::Verified { .. }) {
                continue;
            }
            unfinished = true;
            if !matches!(job.state, FetchState::Wanted)
                || job
                    .sources
                    .values()
                    .any(|source| source.retry_after_ms <= now_ms)
                || !job.late_responses.is_empty()
            {
                return false;
            }
        }
        unfinished
    }

    /// True only when unfinished jobs have no advertised source, request in
    /// flight, locally owned bytes under verification, or late correlated
    /// response. Sources reach this state through disconnect, explicit
    /// unavailability/authentication failure, or the bounded transport-failure
    /// budget. `Busy` and ordinary backoff never make a plan extinct.
    pub fn unfinished_transport_is_extinct(&self) -> bool {
        let mut unfinished = false;
        for job in self.jobs.values() {
            if matches!(job.state, FetchState::Verified { .. }) {
                continue;
            }
            unfinished = true;
            if !matches!(job.state, FetchState::Wanted)
                || !job.sources.is_empty()
                || !job.late_responses.is_empty()
            {
                return false;
            }
        }
        unfinished
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FetchCounts {
    pub wanted: usize,
    pub in_flight: usize,
    pub received: usize,
    pub verified: usize,
}

fn choose_source(
    job: &FetchJob,
    exclude: Option<(PeerId, FailureDomain)>,
    now_ms: u64,
) -> Option<PeerId> {
    job.sources
        .iter()
        .filter(|(peer, source)| {
            source.retry_after_ms <= now_ms
                && exclude.is_none_or(|(excluded_peer, excluded_domain)| {
                    **peer != excluded_peer && source.failure_domain != excluded_domain
                })
                && job
                    .selected_object
                    .is_none_or(|selected| source.object == selected)
        })
        .min_by_key(|(peer, source)| (source.failures, peer.to_bytes()))
        .map(|(peer, _)| *peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::types::{BlockBodyClaimId, BlockBodyObjectId};

    fn body(height: u64, byte: u8) -> (ObjectClaimId, ObjectId) {
        let claim = BlockBodyClaimId {
            height,
            block_hash: [byte; 32],
        };
        (
            ObjectClaimId::BlockBody(claim),
            ObjectId::BlockBody(BlockBodyObjectId {
                claim,
                byte_digest: [byte.wrapping_add(1); 32],
                encoded_len: 100,
            }),
        )
    }

    #[test]
    fn source_failure_rotates_only_the_exact_object() {
        let mut fetcher = ObjectFetcher::new();
        let (first_claim, first_object) = body(1, 1);
        let (second_claim, second_object) = body(2, 2);
        let first_peer = PeerId::random();
        let alternate = PeerId::random();
        fetcher.want(first_claim);
        fetcher.want(second_claim);
        fetcher
            .advertise(first_claim, first_peer, FailureDomain(1), first_object)
            .unwrap();
        fetcher
            .advertise(first_claim, alternate, FailureDomain(2), first_object)
            .unwrap();
        fetcher
            .advertise(second_claim, first_peer, FailureDomain(1), second_object)
            .unwrap();

        let assignment = fetcher.start_primary(first_claim, 0).unwrap();
        fetcher
            .record_progress(first_claim, assignment.peer, 40, 1)
            .unwrap();
        let second = fetcher.start_primary(second_claim, 0).unwrap();
        fetcher
            .finish_receive(second_claim, second.peer, second_object)
            .unwrap();
        fetcher.mark_verified(second_claim, second_object).unwrap();

        let expected_replacement = if assignment.peer == first_peer {
            alternate
        } else {
            first_peer
        };
        fetcher.fail_source(first_claim, assignment.peer).unwrap();
        let replacement = fetcher.start_primary(first_claim, 2).unwrap();
        assert_eq!(replacement.peer, expected_replacement);
        assert_eq!(replacement.resumed_bytes, 40);
        assert_eq!(
            fetcher.state(second_claim),
            Some(FetchState::Verified {
                object: second_object
            })
        );
    }

    #[test]
    fn transport_extinction_waits_for_local_or_remote_progress_to_finish() {
        let (claim, object) = body(1, 1);
        let peer = PeerId::random();
        let mut fetcher = ObjectFetcher::new();
        fetcher.want(claim);
        assert!(fetcher.unfinished_transport_is_stalled(0));
        assert!(fetcher.unfinished_transport_is_extinct());

        fetcher
            .advertise(claim, peer, FailureDomain(1), object)
            .unwrap();
        assert!(!fetcher.unfinished_transport_is_stalled(0));
        assert!(!fetcher.unfinished_transport_is_extinct());
        fetcher.start_primary(claim, 0).unwrap();
        assert!(!fetcher.unfinished_transport_is_stalled(0));
        assert!(!fetcher.unfinished_transport_is_extinct());
        fetcher.finish_receive(claim, peer, object).unwrap();
        fetcher.disconnect(peer);
        assert!(!fetcher.unfinished_transport_is_stalled(0));
        assert!(!fetcher.unfinished_transport_is_extinct());
        fetcher.mark_verified(claim, object).unwrap();
        assert!(!fetcher.unfinished_transport_is_stalled(0));
        assert!(!fetcher.unfinished_transport_is_extinct());
    }

    #[test]
    fn failed_source_is_parked_before_it_can_be_selected_again() {
        let (claim, object) = body(1, 1);
        let peer = PeerId::random();
        let mut fetcher = ObjectFetcher::new();
        fetcher.want(claim);
        fetcher
            .advertise(claim, peer, FailureDomain(1), object)
            .unwrap();
        fetcher.start_primary(claim, 10).unwrap();
        fetcher.fail_source_at(claim, peer, 10).unwrap();

        assert!(fetcher.unfinished_transport_is_stalled(10));
        assert!(!fetcher.unfinished_transport_is_extinct());
        assert_eq!(
            fetcher.start_primary(claim, 1_009),
            Err(FetchError::NoSource)
        );
        assert_eq!(fetcher.start_primary(claim, 1_010).unwrap().peer, peer);
    }

    #[test]
    fn repeated_transport_failure_exhausts_only_that_plan_source() {
        let (claim, object) = body(1, 1);
        let peer = PeerId::random();
        let mut fetcher = ObjectFetcher::new();
        fetcher.want(claim);
        fetcher
            .advertise(claim, peer, FailureDomain(1), object)
            .unwrap();

        for now_ms in [0, 1_000, 3_000] {
            fetcher.start_primary(claim, now_ms).unwrap();
            fetcher.fail_source_at(claim, peer, now_ms).unwrap();
        }

        assert!(fetcher.unfinished_transport_is_stalled(3_000));
        assert!(fetcher.unfinished_transport_is_extinct());
        assert_eq!(
            fetcher.start_primary(claim, u64::MAX),
            Err(FetchError::NoSource)
        );
        assert!(!fetcher
            .advertise_new(claim, peer, FailureDomain(1), object)
            .unwrap());
    }

    #[test]
    fn reconnect_does_not_reset_source_history_or_plan_progress() {
        let (claim, object) = body(1, 1);
        let peer = PeerId::random();
        let mut fetcher = ObjectFetcher::new();
        fetcher.want(claim);
        assert!(fetcher
            .advertise_new(claim, peer, FailureDomain(1), object)
            .unwrap());

        for now_ms in [0, 1_000, 3_000] {
            fetcher.start_primary(claim, now_ms).unwrap();
            fetcher.fail_source_at(claim, peer, now_ms).unwrap();
            fetcher.disconnect(peer);
            assert!(!fetcher
                .advertise_new(claim, peer, FailureDomain(1), object)
                .unwrap());
        }

        assert!(fetcher.unfinished_transport_is_extinct());
        assert_eq!(
            fetcher.start_primary(claim, u64::MAX),
            Err(FetchError::NoSource)
        );
    }

    #[test]
    fn hedge_requires_no_progress_and_a_distinct_failure_domain() {
        let mut fetcher = ObjectFetcher::new();
        let (claim, object) = body(1, 7);
        let primary = PeerId::random();
        let same_domain = PeerId::random();
        let alternate = PeerId::random();
        fetcher.want(claim);
        fetcher
            .advertise(claim, primary, FailureDomain(1), object)
            .unwrap();
        fetcher
            .advertise(claim, same_domain, FailureDomain(1), object)
            .unwrap();
        fetcher
            .advertise(claim, alternate, FailureDomain(2), object)
            .unwrap();
        let primary_assignment = fetcher.start_primary(claim, 10).unwrap();
        assert_eq!(
            fetcher.start_hedge(claim, 19, 10),
            Err(FetchError::InvalidState)
        );
        let hedge = fetcher.start_hedge(claim, 20, 10).unwrap();
        assert_ne!(hedge.peer, primary_assignment.peer);
        let primary_domain = fetcher.jobs[&claim].sources[&primary_assignment.peer].failure_domain;
        assert_ne!(
            fetcher.jobs[&claim].sources[&hedge.peer].failure_domain,
            primary_domain
        );
    }

    #[test]
    fn claim_mismatch_is_rejected_before_assignment() {
        let mut fetcher = ObjectFetcher::new();
        let (claim, _) = body(1, 1);
        let (_, other_object) = body(2, 2);
        fetcher.want(claim);
        assert_eq!(
            fetcher.advertise(claim, PeerId::random(), FailureDomain(1), other_object),
            Err(FetchError::ClaimMismatch)
        );
        assert_eq!(fetcher.start_primary(claim, 0), Err(FetchError::NoSource));
    }

    #[test]
    fn disconnect_never_discards_verified_progress() {
        let mut fetcher = ObjectFetcher::new();
        let (claim, object) = body(1, 1);
        let peer = PeerId::random();
        fetcher.want(claim);
        fetcher
            .advertise(claim, peer, FailureDomain(1), object)
            .unwrap();
        fetcher.start_primary(claim, 0).unwrap();
        fetcher.finish_receive(claim, peer, object).unwrap();
        fetcher.mark_verified(claim, object).unwrap();
        fetcher.disconnect(peer);
        assert_eq!(fetcher.state(claim), Some(FetchState::Verified { object }));
    }

    #[test]
    fn disconnect_preserves_received_bytes_until_verification() {
        let mut fetcher = ObjectFetcher::new();
        let (claim, object) = body(1, 1);
        let peer = PeerId::random();
        fetcher.want(claim);
        fetcher
            .advertise(claim, peer, FailureDomain(1), object)
            .unwrap();
        fetcher.start_primary(claim, 0).unwrap();
        fetcher.finish_receive(claim, peer, object).unwrap();

        fetcher.disconnect(peer);

        assert_eq!(
            fetcher.state(claim),
            Some(FetchState::Received {
                source: peer,
                object,
            })
        );
        fetcher.mark_verified(claim, object).unwrap();
        assert_eq!(fetcher.state(claim), Some(FetchState::Verified { object }));
    }

    #[test]
    fn queued_exact_response_survives_disconnect_overtaking_its_lane() {
        let mut fetcher = ObjectFetcher::new();
        let (claim, object) = body(1, 1);
        let disconnected = PeerId::random();
        let alternate = PeerId::random();
        fetcher.want(claim);
        fetcher
            .advertise(claim, disconnected, FailureDomain(1), object)
            .unwrap();
        fetcher.start_primary(claim, 0).unwrap();

        fetcher.disconnect(disconnected);
        fetcher
            .advertise(claim, alternate, FailureDomain(2), object)
            .unwrap();
        let retry = fetcher.start_primary(claim, 1).unwrap();
        assert_eq!(retry.peer, alternate);

        // The old response was already decoded before disconnect but reached
        // this runtime later through the lower-priority payload lane.
        fetcher.finish_receive(claim, disconnected, object).unwrap();
        fetcher.mark_verified(claim, object).unwrap();
        assert_eq!(fetcher.state(claim), Some(FetchState::Verified { object }));
    }

    #[test]
    fn explicit_unavailable_source_is_not_retried_forever() {
        let mut fetcher = ObjectFetcher::new();
        let (claim, first_encoding) = body(1, 1);
        let (_, mut second_encoding) = body(1, 1);
        let ObjectId::BlockBody(ref mut second) = second_encoding else {
            unreachable!()
        };
        second.byte_digest[0] ^= 0x80;
        let first = PeerId::random();
        let second = PeerId::random();
        fetcher.want(claim);
        fetcher
            .advertise(claim, first, FailureDomain(1), first_encoding)
            .unwrap();
        fetcher
            .advertise(claim, second, FailureDomain(2), second_encoding)
            .unwrap();

        let assignment = fetcher.start_primary(claim, 0).unwrap();
        fetcher.mark_unavailable(claim, assignment.peer).unwrap();
        let replacement = fetcher.start_primary(claim, 1).unwrap();
        assert_ne!(replacement.peer, assignment.peer);
        assert_ne!(replacement.object, assignment.object);

        fetcher.mark_unavailable(claim, replacement.peer).unwrap();
        fetcher
            .advertise(claim, assignment.peer, FailureDomain(1), first_encoding)
            .unwrap();
        assert_eq!(fetcher.start_primary(claim, 2), Err(FetchError::NoSource));
    }

    #[test]
    fn authenticated_corruption_quarantines_source_for_the_whole_plan() {
        let mut fetcher = ObjectFetcher::new();
        let corrupt = PeerId::random();
        let alternate = PeerId::random();
        let (first_claim, first_object) = body(1, 1);
        let (second_claim, second_object) = body(2, 2);
        for (claim, object) in [(first_claim, first_object), (second_claim, second_object)] {
            fetcher.want(claim);
            fetcher
                .advertise(claim, corrupt, FailureDomain(1), object)
                .unwrap();
            fetcher
                .advertise(claim, alternate, FailureDomain(2), object)
                .unwrap();
        }

        fetcher.quarantine_source(corrupt);

        assert_eq!(
            fetcher.start_primary(first_claim, 0).unwrap().peer,
            alternate
        );
        assert_eq!(
            fetcher.start_primary(second_claim, 0).unwrap().peer,
            alternate
        );
        assert_eq!(
            fetcher.advertise(second_claim, corrupt, FailureDomain(1), second_object),
            Ok(())
        );
        assert!(!fetcher.jobs[&second_claim].sources.contains_key(&corrupt));
    }

    #[test]
    fn busy_source_is_retained_but_not_retried_before_deadline() {
        let mut fetcher = ObjectFetcher::new();
        let (claim, object) = body(1, 1);
        let peer = PeerId::random();
        fetcher.want(claim);
        fetcher
            .advertise(claim, peer, FailureDomain(1), object)
            .unwrap();

        let assignment = fetcher.start_primary(claim, 10).unwrap();
        assert_eq!(assignment.peer, peer);
        fetcher.busy_source(claim, peer, 100).unwrap();
        assert_eq!(fetcher.state(claim), Some(FetchState::Wanted));
        assert!(fetcher.unfinished_transport_is_stalled(99));
        assert!(!fetcher.unfinished_transport_is_extinct());
        assert_eq!(fetcher.start_primary(claim, 99), Err(FetchError::NoSource));
        assert_eq!(fetcher.start_primary(claim, 100).unwrap().peer, peer);
        assert_eq!(fetcher.jobs[&claim].sources[&peer].failures, 0);
    }

    #[test]
    fn local_queue_backpressure_does_not_penalize_or_forget_the_source() {
        let mut fetcher = ObjectFetcher::new();
        let (claim, object) = body(1, 1);
        let peer = PeerId::random();
        fetcher.want(claim);
        fetcher
            .advertise(claim, peer, FailureDomain(1), object)
            .unwrap();

        let first = fetcher.start_primary(claim, 10).unwrap();
        fetcher.defer_source(claim, peer).unwrap();
        assert_eq!(fetcher.state(claim), Some(FetchState::Wanted));

        let retried = fetcher.start_primary(claim, 11).unwrap();
        assert_eq!(retried.peer, first.peer);
        assert_eq!(retried.object, first.object);
    }

    #[test]
    fn expired_late_response_releases_a_disappeared_exact_encoding() {
        let mut fetcher = ObjectFetcher::new();
        let (claim, first_object) = body(1, 1);
        let second_object = match first_object {
            ObjectId::BlockBody(mut object) => {
                object.byte_digest = [0xAA; 32];
                ObjectId::BlockBody(object)
            }
            _ => unreachable!("test helper creates one block-body object"),
        };
        let first_peer = PeerId::random();
        let second_peer = PeerId::random();
        fetcher.want(claim);
        fetcher
            .advertise(claim, first_peer, FailureDomain(1), first_object)
            .unwrap();
        assert_eq!(
            fetcher.start_primary(claim, 0).unwrap().object,
            first_object
        );
        fetcher.disconnect(first_peer);
        fetcher
            .advertise(claim, second_peer, FailureDomain(2), second_object)
            .unwrap();

        assert_eq!(fetcher.start_primary(claim, 1), Err(FetchError::NoSource));
        fetcher.forget_late_response(claim, first_peer, first_object);
        let replacement = fetcher.start_primary(claim, 2).unwrap();
        assert_eq!(replacement.peer, second_peer);
        assert_eq!(replacement.object, second_object);
    }
}
