// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact-object scheduling with source rotation and progress preservation.

use std::collections::HashMap;

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
}

#[derive(Debug)]
struct FetchJob {
    state: FetchState,
    sources: HashMap<PeerId, Source>,
    selected_object: Option<ObjectId>,
    partial_bytes: u32,
    last_progress_ms: Option<u64>,
}

impl FetchJob {
    fn new() -> Self {
        Self {
            state: FetchState::Wanted,
            sources: HashMap::new(),
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
        if object.claim() != claim {
            return Err(FetchError::ClaimMismatch);
        }
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        job.sources.insert(
            peer,
            Source {
                object,
                failure_domain,
                failures: job.sources.get(&peer).map_or(0, |source| source.failures),
            },
        );
        Ok(())
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

        let selected = choose_source(job, None).ok_or(FetchError::NoSource)?;
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
        let selected = choose_source(job, Some((primary, primary_source.failure_domain)))
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
        Ok(())
    }

    pub fn finish_receive(
        &mut self,
        claim: ObjectClaimId,
        peer: PeerId,
        object: ObjectId,
    ) -> Result<(), FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        if !job.active_source(peer) {
            return Err(FetchError::InactiveSource);
        }
        if object.claim() != claim || job.selected_object != Some(object) {
            return Err(FetchError::ObjectMismatch);
        }
        job.partial_bytes = object.encoded_len().unwrap_or(job.partial_bytes);
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
        job.state = FetchState::Verified { object };
        Ok(())
    }

    /// Fail one source lease. Verified objects and all unrelated jobs survive.
    pub fn fail_source(&mut self, claim: ObjectClaimId, peer: PeerId) -> Result<(), FetchError> {
        let job = self.jobs.get_mut(&claim).ok_or(FetchError::UnknownClaim)?;
        if let Some(source) = job.sources.get_mut(&peer) {
            source.failures = source.failures.saturating_add(1);
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
        Ok(())
    }

    /// Drop a dead transport source everywhere without discarding any job.
    pub fn disconnect(&mut self, peer: PeerId) {
        for job in self.jobs.values_mut() {
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
                FetchState::Received { source, .. } if source == peer => {
                    job.state = FetchState::Wanted;
                    Some(())
                }
                _ => None,
            };
            job.sources.remove(&peer);
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
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FetchCounts {
    pub wanted: usize,
    pub in_flight: usize,
    pub received: usize,
    pub verified: usize,
}

fn choose_source(job: &FetchJob, exclude: Option<(PeerId, FailureDomain)>) -> Option<PeerId> {
    job.sources
        .iter()
        .filter(|(peer, source)| {
            exclude.is_none_or(|(excluded_peer, excluded_domain)| {
                **peer != excluded_peer && source.failure_domain != excluded_domain
            }) && job
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
}
