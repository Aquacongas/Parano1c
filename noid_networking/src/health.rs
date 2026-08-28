// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Lock-free publication of networking and synchronization health.

use tokio::sync::watch;

use super::{
    mining_readiness::MiningReadinessSnapshot,
    object_fetcher::FetchCounts,
    sync_plan::SyncPlanKind,
    topology::TopologyCounts,
    types::{ChainPoint, PlanId},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncPhase {
    #[default]
    Idle,
    HeaderDiscovery,
    Planning,
    Fetching,
    Verifying,
    Committing,
    WaitingForSource,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueDepths {
    pub control_p0: usize,
    pub live_p1: usize,
    pub historical_p2: usize,
    pub background_p3: usize,
    pub completed_objects: usize,
    pub decoded_bytes_in_use: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhaseTimings {
    pub queue_wait_ms: Option<u64>,
    pub first_byte_ms: Option<u64>,
    pub transfer_ms: Option<u64>,
    pub verify_ms: Option<u64>,
    pub commit_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanProgress {
    pub id: PlanId,
    pub kind: SyncPlanKind,
    pub phase: SyncPhase,
    pub objects: FetchCounts,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkHealthSnapshot {
    pub heartbeat_sequence: u64,
    pub monotonic_ms: u64,
    pub topology: TopologyCounts,
    pub mining: MiningReadinessSnapshot,
    pub committed_tip: Option<ChainPoint>,
    pub best_header_tip: Option<ChainPoint>,
    pub active_plan: Option<PlanProgress>,
    pub queues: QueueDepths,
    pub timings: PhaseTimings,
    pub last_error: Option<String>,
}

/// Single-writer publisher. RPC and GUI readers clone the last immutable
/// value without acquiring the chain database writer lock.
pub struct HealthPublisher {
    current: NetworkHealthSnapshot,
    tx: watch::Sender<NetworkHealthSnapshot>,
}

impl HealthPublisher {
    pub fn new(initial: NetworkHealthSnapshot) -> (Self, HealthSubscriber) {
        let (tx, rx) = watch::channel(initial.clone());
        (
            Self {
                current: initial,
                tx,
            },
            HealthSubscriber { rx },
        )
    }

    pub fn publish(&mut self, update: impl FnOnce(&mut NetworkHealthSnapshot)) {
        update(&mut self.current);
        self.current.heartbeat_sequence = self.current.heartbeat_sequence.saturating_add(1);
        self.tx.send_replace(self.current.clone());
    }

    pub fn current(&self) -> &NetworkHealthSnapshot {
        &self.current
    }

    pub fn subscribe(&self) -> HealthSubscriber {
        HealthSubscriber {
            rx: self.tx.subscribe(),
        }
    }
}

#[derive(Clone)]
pub struct HealthSubscriber {
    rx: watch::Receiver<NetworkHealthSnapshot>,
}

impl HealthSubscriber {
    pub fn latest(&self) -> NetworkHealthSnapshot {
        self.rx.borrow().clone()
    }

    pub async fn changed(&mut self) -> Result<NetworkHealthSnapshot, watch::error::RecvError> {
        self.rx.changed().await?;
        Ok(self.latest())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribers_observe_one_coherent_latest_snapshot() {
        let (mut publisher, subscriber) = HealthPublisher::new(NetworkHealthSnapshot::default());
        publisher.publish(|snapshot| {
            snapshot.monotonic_ms = 100;
            snapshot.topology.raw_connections = 5;
            snapshot.queues.control_p0 = 2;
        });
        publisher.publish(|snapshot| {
            snapshot.monotonic_ms = 101;
            snapshot.topology.dispatchable_peers = 3;
            snapshot.last_error = Some("source unavailable".to_owned());
        });

        let latest = subscriber.latest();
        assert_eq!(latest.heartbeat_sequence, 2);
        assert_eq!(latest.monotonic_ms, 101);
        assert_eq!(latest.topology.raw_connections, 5);
        assert_eq!(latest.topology.dispatchable_peers, 3);
        assert_eq!(latest.queues.control_p0, 2);
        assert_eq!(latest.last_error.as_deref(), Some("source unavailable"));
    }

    #[test]
    fn health_keeps_control_and_bulk_pressure_separate() {
        let (mut publisher, subscriber) = HealthPublisher::new(NetworkHealthSnapshot::default());
        publisher.publish(|snapshot| {
            snapshot.queues.control_p0 = 0;
            snapshot.queues.historical_p2 = 64;
            snapshot.queues.decoded_bytes_in_use = 32 * 1024 * 1024;
            snapshot.timings.first_byte_ms = Some(800);
        });
        let latest = subscriber.latest();
        assert_eq!(latest.queues.control_p0, 0);
        assert_eq!(latest.queues.historical_p2, 64);
        assert_eq!(latest.timings.first_byte_ms, Some(800));
    }
}
