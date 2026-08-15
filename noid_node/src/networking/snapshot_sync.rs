// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Immutable, source-independent snapshot scheduling.

use libp2p::PeerId;
use noid_chain::history_step::HistoryStepTerminalMetadata;
use noid_p2p::protocol::{
    GetStateManifestResponse, VerifiedStateManifest, SNAPSHOT_MANIFEST_FORMAT_VERSION,
};
use thiserror::Error;

use super::{
    object_fetcher::{FetchCounts, FetchError, FetchState, ObjectFetcher},
    sync_plan::{SyncPlan, SyncPlanError},
    types::{
        ChainPoint, FailureDomain, ObjectClaimId, ObjectId, PlanId, SnapshotId, StateSegmentId,
        TerminalClaimId,
    },
};

#[derive(Clone, Debug)]
pub struct SnapshotOffer {
    snapshot: SnapshotId,
    segments: Vec<StateSegmentId>,
    manifest: VerifiedStateManifest,
}

impl SnapshotOffer {
    /// Freeze the exact generation described by an already codec-bounded
    /// manifest. The provider is deliberately absent from this value.
    pub fn from_manifest(manifest: GetStateManifestResponse) -> Result<Self, SnapshotSyncError> {
        let verified =
            VerifiedStateManifest::verify(manifest).ok_or(SnapshotSyncError::InvalidManifest)?;
        Self::from_verified_manifest(verified)
    }

    pub fn from_verified_manifest(
        manifest: VerifiedStateManifest,
    ) -> Result<Self, SnapshotSyncError> {
        if manifest.tip_height == 0 || manifest.format_version != SNAPSHOT_MANIFEST_FORMAT_VERSION {
            return Err(SnapshotSyncError::InvalidManifest);
        }
        let snapshot = SnapshotId {
            boundary: ChainPoint::new(manifest.tip_height, manifest.tip_hash),
            state_root: manifest.state_root,
            manifest_digest: manifest.manifest_digest,
            format_version: manifest.format_version,
        };
        let segments = manifest
            .segment_ids
            .iter()
            .copied()
            .zip(manifest.segment_roots.iter().copied())
            .zip(manifest.segment_lengths.iter().copied())
            .map(|((segment_id, segment_root), encoded_len)| StateSegmentId {
                snapshot,
                segment_id,
                segment_root,
                encoded_len,
            })
            .collect();
        Ok(Self {
            snapshot,
            segments,
            manifest,
        })
    }

    pub const fn snapshot_id(&self) -> SnapshotId {
        self.snapshot
    }

    pub fn manifest(&self) -> &GetStateManifestResponse {
        self.manifest.as_ref()
    }

    pub fn segments(&self) -> &[StateSegmentId] {
        &self.segments
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotSegmentRequest {
    pub peer: PeerId,
    pub segment: StateSegmentId,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotSyncError {
    #[error("the snapshot manifest is empty, malformed, or has an invalid digest")]
    InvalidManifest,
    #[error("the HistoryStep terminal does not bind the snapshot boundary")]
    TerminalMismatch,
    #[error("the offered manifest is not the selected immutable generation")]
    PlanMismatch,
    #[error("the segment is not part of the selected immutable generation")]
    UnknownSegment,
    #[error("the response does not match its exact segment request")]
    CorrelationMismatch,
    #[error("the response length differs from the immutable manifest")]
    ResponseLengthMismatch,
    #[error("the snapshot segment has not been received")]
    SegmentNotReceived,
    #[error("exact-object scheduling failed: {0}")]
    Fetch(#[from] FetchError),
    #[error("the immutable synchronization plan is invalid: {0}")]
    Plan(#[from] SyncPlanError),
}

/// Mutable transport leases for one immutable snapshot plan.
///
/// A disconnect, timeout or full local queue changes only a source lease. The
/// snapshot identity and every independently verified segment survive.
pub struct SnapshotSync {
    offer: SnapshotOffer,
    plan: SyncPlan,
    fetcher: ObjectFetcher,
}

impl SnapshotSync {
    pub fn new(
        initial_peer: PeerId,
        failure_domain: FailureDomain,
        offer: SnapshotOffer,
        terminal_bytes: &[u8],
        boundary_semantic_header_id: [u8; 32],
    ) -> Result<Self, SnapshotSyncError> {
        let metadata = HistoryStepTerminalMetadata::decode_prefix(terminal_bytes)
            .map_err(|_| SnapshotSyncError::TerminalMismatch)?;
        if metadata.terminal_height() != offer.snapshot.boundary.height
            || metadata.terminal_hash() != boundary_semantic_header_id
        {
            return Err(SnapshotSyncError::TerminalMismatch);
        }
        let terminal = TerminalClaimId {
            height: metadata.terminal_height(),
            semantic_header_id: metadata.terminal_hash(),
            proof_class: metadata.class_id(),
        };
        let plan = SyncPlan::snapshot(offer.snapshot, terminal, offer.segments.clone())?;
        let mut sync = Self {
            offer,
            plan,
            fetcher: ObjectFetcher::new(),
        };
        for segment in sync.offer.segments.iter().copied() {
            sync.fetcher.want(ObjectClaimId::StateSegment(segment));
        }
        sync.add_provider(initial_peer, failure_domain, sync.offer.clone())?;
        Ok(sync)
    }

    pub const fn plan(&self) -> &SyncPlan {
        &self.plan
    }

    pub const fn plan_id(&self) -> PlanId {
        self.plan.id()
    }

    pub fn manifest(&self) -> &GetStateManifestResponse {
        self.offer.manifest()
    }

    pub fn add_provider(
        &mut self,
        peer: PeerId,
        failure_domain: FailureDomain,
        offer: SnapshotOffer,
    ) -> Result<(), SnapshotSyncError> {
        if offer.snapshot != self.offer.snapshot
            || offer.segments != self.offer.segments
            || offer.manifest != self.offer.manifest
        {
            return Err(SnapshotSyncError::PlanMismatch);
        }
        for segment in self.offer.segments.iter().copied() {
            self.fetcher.advertise(
                ObjectClaimId::StateSegment(segment),
                peer,
                failure_domain,
                ObjectId::StateSegment(segment),
            )?;
        }
        Ok(())
    }

    /// Schedule at most `limit` exact segments. The production State staging
    /// pipeline uses one; tests may use a larger value to exercise failover.
    pub fn schedule(&mut self, now_ms: u64, limit: usize) -> Vec<SnapshotSegmentRequest> {
        let mut requests = Vec::new();
        for segment in self.offer.segments.iter().copied() {
            if requests.len() >= limit {
                break;
            }
            let claim = ObjectClaimId::StateSegment(segment);
            if self.fetcher.state(claim) != Some(FetchState::Wanted) {
                continue;
            }
            if let Ok(assignment) = self.fetcher.start_primary(claim, now_ms) {
                requests.push(SnapshotSegmentRequest {
                    peer: assignment.peer,
                    segment,
                });
            }
        }
        requests
    }

    pub fn defer_request(
        &mut self,
        request: SnapshotSegmentRequest,
    ) -> Result<(), SnapshotSyncError> {
        self.fetcher
            .defer_source(ObjectClaimId::StateSegment(request.segment), request.peer)?;
        Ok(())
    }

    pub fn request_failed(
        &mut self,
        peer: PeerId,
        segment: StateSegmentId,
        now_ms: u64,
    ) -> Result<(), SnapshotSyncError> {
        self.require_segment(segment)?;
        self.fetcher
            .fail_source_at(ObjectClaimId::StateSegment(segment), peer, now_ms)?;
        Ok(())
    }

    pub fn request_busy(
        &mut self,
        peer: PeerId,
        segment: StateSegmentId,
        retry_at_ms: u64,
    ) -> Result<(), SnapshotSyncError> {
        self.require_segment(segment)?;
        self.fetcher
            .busy_source(ObjectClaimId::StateSegment(segment), peer, retry_at_ms)?;
        Ok(())
    }

    pub fn unavailable(
        &mut self,
        peer: PeerId,
        segment: StateSegmentId,
    ) -> Result<(), SnapshotSyncError> {
        self.require_segment(segment)?;
        self.fetcher
            .mark_unavailable(ObjectClaimId::StateSegment(segment), peer)?;
        Ok(())
    }

    /// Reject a provider for the complete immutable generation after one of
    /// its exact segment payloads fails authenticated length/root/semantic
    /// verification. Transport failures and honest per-object unavailability
    /// must continue to use the narrower methods above.
    pub fn reject_provider(
        &mut self,
        peer: PeerId,
        segment: StateSegmentId,
    ) -> Result<(), SnapshotSyncError> {
        self.require_segment(segment)?;
        self.fetcher
            .reject_source_object(ObjectClaimId::StateSegment(segment), peer)?;
        self.fetcher.quarantine_source(peer);
        Ok(())
    }

    /// Retire one provider from the complete immutable generation after its
    /// exact manifest service has proved malformed. No verified object or
    /// other provider is disturbed.
    pub fn quarantine_provider(&mut self, peer: PeerId) {
        self.fetcher.quarantine_source(peer);
    }

    pub fn accept_response(
        &mut self,
        peer: PeerId,
        segment: StateSegmentId,
        response_len: usize,
    ) -> Result<(), SnapshotSyncError> {
        self.require_segment(segment)?;
        if usize::try_from(segment.encoded_len).ok() != Some(response_len) {
            return Err(SnapshotSyncError::ResponseLengthMismatch);
        }
        self.fetcher.finish_receive(
            ObjectClaimId::StateSegment(segment),
            peer,
            ObjectId::StateSegment(segment),
        )?;
        Ok(())
    }

    /// Called only after the existing State segment verifier has checked the
    /// sparse encoding and exact root and sealed it to staging storage.
    pub fn mark_verified(&mut self, segment: StateSegmentId) -> Result<(), SnapshotSyncError> {
        self.require_segment(segment)?;
        let claim = ObjectClaimId::StateSegment(segment);
        if !matches!(self.fetcher.state(claim), Some(FetchState::Received { .. })) {
            return Err(SnapshotSyncError::SegmentNotReceived);
        }
        self.fetcher
            .mark_verified(claim, ObjectId::StateSegment(segment))?;
        Ok(())
    }

    pub fn disconnect(&mut self, peer: PeerId) {
        self.fetcher.disconnect(peer);
    }

    pub fn all_segments_verified(&self) -> bool {
        self.offer.segments.iter().all(|segment| {
            matches!(
                self.fetcher.state(ObjectClaimId::StateSegment(*segment)),
                Some(FetchState::Verified { .. })
            )
        })
    }

    pub fn counts(&self) -> FetchCounts {
        self.fetcher.counts()
    }

    pub fn unfinished_transport_is_stalled(&self, now_ms: u64) -> bool {
        self.fetcher.unfinished_transport_is_stalled(now_ms)
    }

    pub fn unfinished_transport_is_extinct(&self) -> bool {
        self.fetcher.unfinished_transport_is_extinct()
    }

    pub fn segment(&self, segment_id: u16) -> Option<StateSegmentId> {
        self.offer
            .segments
            .iter()
            .copied()
            .find(|segment| segment.segment_id == segment_id)
    }

    fn require_segment(&self, segment: StateSegmentId) -> Result<(), SnapshotSyncError> {
        if segment.snapshot != self.offer.snapshot || !self.offer.segments.contains(&segment) {
            return Err(SnapshotSyncError::UnknownSegment);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> GetStateManifestResponse {
        let mut manifest = GetStateManifestResponse {
            tip_height: 100,
            tip_hash: [1; 32],
            cumulative_chainwork: [2; 32],
            format_version: SNAPSHOT_MANIFEST_FORMAT_VERSION,
            state_root: [3; 32],
            log_slots: 24,
            active_slot_count: 2,
            alloc_counter: 3,
            eff_log: 16,
            bridge_tip_height: 100,
            bridge_tip_hash: [1; 32],
            bridge_cumulative_chainwork: [2; 32],
            segment_ids: vec![7, 9],
            segment_roots: vec![[7; 32], [9; 32]],
            // Canonical sparse-segment framing: 9-byte header plus one
            // 50-byte live slot in each segment.
            segment_lengths: vec![59, 59],
            ..Default::default()
        };
        assert!(manifest.seal_manifest_digest());
        manifest
    }

    fn terminal_bytes(offer: &SnapshotOffer, semantic_header_id: [u8; 32]) -> Vec<u8> {
        HistoryStepTerminalMetadata::new(offer.snapshot.boundary.height, semantic_header_id, 0)
            .unwrap()
            .encode_prefix()
            .to_vec()
    }

    #[test]
    fn plan_binds_every_segment_and_not_the_provider() {
        let first = PeerId::random();
        let second = PeerId::random();
        let offer = SnapshotOffer::from_manifest(manifest()).unwrap();
        let semantic_header_id = [6; 32];
        let terminal = terminal_bytes(&offer, semantic_header_id);
        let mut sync = SnapshotSync::new(
            first,
            FailureDomain(1),
            offer.clone(),
            &terminal,
            semantic_header_id,
        )
        .unwrap();
        let plan_id = sync.plan_id();
        sync.add_provider(second, FailureDomain(2), offer).unwrap();
        assert_eq!(sync.plan_id(), plan_id);
        assert_eq!(sync.plan.required_objects().len(), 4);
    }

    #[test]
    fn disconnect_rotates_only_the_source_and_keeps_verified_segments() {
        let first = PeerId::random();
        let second = PeerId::random();
        let offer = SnapshotOffer::from_manifest(manifest()).unwrap();
        let semantic_header_id = [6; 32];
        let terminal = terminal_bytes(&offer, semantic_header_id);
        let mut sync = SnapshotSync::new(
            first,
            FailureDomain(1),
            offer.clone(),
            &terminal,
            semantic_header_id,
        )
        .unwrap();
        sync.add_provider(second, FailureDomain(2), offer).unwrap();

        let first_request = sync.schedule(0, 1).pop().unwrap();
        sync.accept_response(
            first_request.peer,
            first_request.segment,
            first_request.segment.encoded_len as usize,
        )
        .unwrap();
        sync.mark_verified(first_request.segment).unwrap();
        sync.disconnect(first_request.peer);

        let next = sync.schedule(1, 1).pop().unwrap();
        assert_ne!(next.segment, first_request.segment);
        assert_ne!(next.peer, first_request.peer);
    }

    #[test]
    fn disconnect_after_receive_does_not_invalidate_local_staging() {
        let first = PeerId::random();
        let second = PeerId::random();
        let offer = SnapshotOffer::from_manifest(manifest()).unwrap();
        let semantic_header_id = [6; 32];
        let terminal = terminal_bytes(&offer, semantic_header_id);
        let mut sync = SnapshotSync::new(
            first,
            FailureDomain(1),
            offer.clone(),
            &terminal,
            semantic_header_id,
        )
        .unwrap();
        sync.add_provider(second, FailureDomain(2), offer).unwrap();

        let received = sync.schedule(0, 1).pop().unwrap();
        sync.accept_response(
            received.peer,
            received.segment,
            received.segment.encoded_len as usize,
        )
        .unwrap();
        sync.disconnect(received.peer);

        // The transport has gone away, but the bytes are already owned by the
        // staging worker. Its successful exact-root result must still advance
        // this segment to Verified instead of forcing a redownload or fatal
        // "lost authority" path.
        sync.mark_verified(received.segment).unwrap();
        assert_eq!(sync.counts().verified, 1);
        let next = sync.schedule(1, 1).pop().unwrap();
        assert_ne!(next.segment, received.segment);
    }

    #[test]
    fn queued_segment_response_survives_disconnect_event_overtake() {
        let disconnected = PeerId::random();
        let alternate = PeerId::random();
        let offer = SnapshotOffer::from_manifest(manifest()).unwrap();
        let semantic_header_id = [6; 32];
        let terminal = terminal_bytes(&offer, semantic_header_id);
        let mut sync = SnapshotSync::new(
            disconnected,
            FailureDomain(1),
            offer.clone(),
            &terminal,
            semantic_header_id,
        )
        .unwrap();
        let queued = sync.schedule(0, 1).pop().unwrap();
        assert_eq!(queued.peer, disconnected);
        sync.add_provider(alternate, FailureDomain(2), offer)
            .unwrap();
        sync.disconnect(disconnected);
        let retry = sync.schedule(1, 1).pop().unwrap();
        assert_eq!(retry.peer, alternate);

        // The bytes were decoded before transport close, but the control lane
        // delivered PeerDisconnected before this historical payload event.
        sync.accept_response(
            queued.peer,
            queued.segment,
            queued.segment.encoded_len as usize,
        )
        .unwrap();
        sync.mark_verified(queued.segment).unwrap();
        assert_eq!(sync.counts().verified, 1);
    }

    #[test]
    fn corrupt_segment_quarantines_provider_across_the_generation() {
        let corrupt = PeerId::random();
        let alternate = PeerId::random();
        let offer = SnapshotOffer::from_manifest(manifest()).unwrap();
        let semantic_header_id = [6; 32];
        let terminal = terminal_bytes(&offer, semantic_header_id);
        let mut sync = SnapshotSync::new(
            corrupt,
            FailureDomain(1),
            offer.clone(),
            &terminal,
            semantic_header_id,
        )
        .unwrap();

        let rejected = sync.schedule(0, 1).pop().unwrap();
        assert_eq!(rejected.peer, corrupt);
        sync.accept_response(
            rejected.peer,
            rejected.segment,
            rejected.segment.encoded_len as usize,
        )
        .unwrap();
        sync.reject_provider(corrupt, rejected.segment).unwrap();
        sync.add_provider(alternate, FailureDomain(2), offer.clone())
            .unwrap();
        sync.add_provider(corrupt, FailureDomain(1), offer).unwrap();

        let requests = sync.schedule(1, 2);
        assert!(
            !requests.is_empty(),
            "rejected Received bytes must become Wanted"
        );
        for request in &requests {
            assert_eq!(request.peer, alternate);
        }
        let retry = requests
            .into_iter()
            .find(|request| request.segment == rejected.segment)
            .expect("the rejected exact segment is scheduled from the alternate");
        sync.accept_response(
            retry.peer,
            retry.segment,
            retry.segment.encoded_len as usize,
        )
        .unwrap();
        sync.mark_verified(retry.segment).unwrap();
        assert_eq!(sync.counts().verified, 1);
    }

    #[test]
    fn local_queue_pressure_preserves_the_exact_request() {
        let peer = PeerId::random();
        let offer = SnapshotOffer::from_manifest(manifest()).unwrap();
        let semantic_header_id = [6; 32];
        let terminal = terminal_bytes(&offer, semantic_header_id);
        let mut sync =
            SnapshotSync::new(peer, FailureDomain(1), offer, &terminal, semantic_header_id)
                .unwrap();
        let first = sync.schedule(0, 1).pop().unwrap();
        sync.defer_request(first).unwrap();
        assert_eq!(sync.schedule(1, 1).pop(), Some(first));
    }

    #[test]
    fn remote_busy_keeps_the_provider_and_delays_retry() {
        let peer = PeerId::random();
        let mut one_segment = manifest();
        one_segment.segment_ids.truncate(1);
        one_segment.segment_roots.truncate(1);
        one_segment.segment_lengths.truncate(1);
        one_segment.active_slot_count = 1;
        assert!(one_segment.seal_manifest_digest());
        let offer = SnapshotOffer::from_manifest(one_segment).unwrap();
        let semantic_header_id = [6; 32];
        let terminal = terminal_bytes(&offer, semantic_header_id);
        let mut sync =
            SnapshotSync::new(peer, FailureDomain(1), offer, &terminal, semantic_header_id)
                .unwrap();
        let request = sync.schedule(10, 1).pop().unwrap();
        sync.request_busy(peer, request.segment, 100).unwrap();
        assert!(sync.schedule(99, 1).is_empty());
        assert_eq!(sync.schedule(100, 1).pop(), Some(request));
    }
}
