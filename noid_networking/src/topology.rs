// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transport topology bookkeeping, separate from sync and consensus policy.

use std::collections::{HashMap, HashSet};

use libp2p::{swarm::ConnectionId, PeerId};
use thiserror::Error;

use super::types::FailureDomain;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionPath {
    Direct,
    Relayed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionRecord {
    pub peer: PeerId,
    pub failure_domain: Option<FailureDomain>,
    pub direction: ConnectionDirection,
    pub path: ConnectionPath,
    pub identified: bool,
    pub authenticated: bool,
    pub closing: bool,
}

impl ConnectionRecord {
    pub const fn dispatchable(self) -> bool {
        self.identified && self.authenticated && !self.closing
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TopologyCounts {
    pub raw_connections: usize,
    pub identified_connections: usize,
    pub authenticated_connections: usize,
    pub dispatchable_connections: usize,
    pub connected_peers: usize,
    pub dispatchable_peers: usize,
    pub dispatchable_failure_domains: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TopologyError {
    #[error("connection id is already assigned to another path")]
    DuplicateConnectionId,
    #[error("connection id is unknown")]
    UnknownConnection,
}

/// Exact-connection lifecycle state. It deliberately has no authority to
/// choose branches, reset sync or enable mining.
#[derive(Default)]
pub struct TopologyActor {
    connections: HashMap<ConnectionId, ConnectionRecord>,
}

impl TopologyActor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn established(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        failure_domain: Option<FailureDomain>,
        direction: ConnectionDirection,
        path: ConnectionPath,
    ) -> Result<(), TopologyError> {
        let record = ConnectionRecord {
            peer,
            failure_domain,
            direction,
            path,
            identified: false,
            authenticated: false,
            closing: false,
        };
        match self.connections.get(&connection_id) {
            Some(existing) if existing == &record => Ok(()),
            Some(_) => Err(TopologyError::DuplicateConnectionId),
            None => {
                self.connections.insert(connection_id, record);
                Ok(())
            }
        }
    }

    pub fn mark_identified(&mut self, connection_id: ConnectionId) -> Result<(), TopologyError> {
        let record = self
            .connections
            .get_mut(&connection_id)
            .ok_or(TopologyError::UnknownConnection)?;
        record.identified = true;
        Ok(())
    }

    pub fn mark_authenticated(&mut self, connection_id: ConnectionId) -> Result<(), TopologyError> {
        let record = self
            .connections
            .get_mut(&connection_id)
            .ok_or(TopologyError::UnknownConnection)?;
        record.identified = true;
        record.authenticated = true;
        Ok(())
    }

    pub fn mark_closing(&mut self, connection_id: ConnectionId) -> Result<(), TopologyError> {
        let record = self
            .connections
            .get_mut(&connection_id)
            .ok_or(TopologyError::UnknownConnection)?;
        record.closing = true;
        Ok(())
    }

    pub fn closed(&mut self, connection_id: ConnectionId) -> Option<ConnectionRecord> {
        self.connections.remove(&connection_id)
    }

    pub fn connection(&self, connection_id: ConnectionId) -> Option<ConnectionRecord> {
        self.connections.get(&connection_id).copied()
    }

    pub fn peer_is_dispatchable(&self, peer: PeerId) -> bool {
        self.connections
            .values()
            .any(|record| record.peer == peer && record.dispatchable())
    }

    pub fn dispatchable_peers(&self) -> HashSet<PeerId> {
        self.connections
            .values()
            .filter(|record| record.dispatchable())
            .map(|record| record.peer)
            .collect()
    }

    pub fn dispatchable_failure_domains(&self) -> HashSet<FailureDomain> {
        self.connections
            .values()
            .filter(|record| record.dispatchable())
            .filter_map(|record| record.failure_domain)
            .collect()
    }

    pub fn counts(&self) -> TopologyCounts {
        let connected_peers = self
            .connections
            .values()
            .map(|record| record.peer)
            .collect::<HashSet<_>>();
        let dispatchable_peers = self.dispatchable_peers();
        TopologyCounts {
            raw_connections: self.connections.len(),
            identified_connections: self
                .connections
                .values()
                .filter(|record| record.identified)
                .count(),
            authenticated_connections: self
                .connections
                .values()
                .filter(|record| record.authenticated)
                .count(),
            dispatchable_connections: self
                .connections
                .values()
                .filter(|record| record.dispatchable())
                .count(),
            connected_peers: connected_peers.len(),
            dispatchable_peers: dispatchable_peers.len(),
            dispatchable_failure_domains: self.dispatchable_failure_domains().len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_connection_close_preserves_a_surviving_peer_path() {
        let peer = PeerId::random();
        let first = ConnectionId::new_unchecked(1);
        let second = ConnectionId::new_unchecked(2);
        let mut topology = TopologyActor::new();
        topology
            .established(
                first,
                peer,
                Some(FailureDomain(1)),
                ConnectionDirection::Outbound,
                ConnectionPath::Direct,
            )
            .unwrap();
        topology
            .established(
                second,
                peer,
                Some(FailureDomain(1)),
                ConnectionDirection::Inbound,
                ConnectionPath::Direct,
            )
            .unwrap();
        topology.mark_authenticated(first).unwrap();
        topology.mark_authenticated(second).unwrap();
        assert_eq!(topology.counts().dispatchable_connections, 2);
        assert_eq!(topology.counts().dispatchable_peers, 1);

        topology.mark_closing(first).unwrap();
        assert!(topology.peer_is_dispatchable(peer));
        assert_eq!(topology.counts().dispatchable_connections, 1);
        topology.closed(first);
        assert!(topology.peer_is_dispatchable(peer));
    }

    #[test]
    fn closing_or_unauthenticated_paths_are_not_dispatchable() {
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(7);
        let mut topology = TopologyActor::new();
        topology
            .established(
                connection,
                peer,
                Some(FailureDomain(3)),
                ConnectionDirection::Outbound,
                ConnectionPath::Relayed,
            )
            .unwrap();
        assert!(!topology.peer_is_dispatchable(peer));
        topology.mark_authenticated(connection).unwrap();
        assert!(topology.peer_is_dispatchable(peer));
        topology.mark_closing(connection).unwrap();
        assert!(!topology.peer_is_dispatchable(peer));
    }

    #[test]
    fn connection_id_cannot_be_reassigned() {
        let connection = ConnectionId::new_unchecked(9);
        let mut topology = TopologyActor::new();
        topology
            .established(
                connection,
                PeerId::random(),
                None,
                ConnectionDirection::Outbound,
                ConnectionPath::Direct,
            )
            .unwrap();
        assert_eq!(
            topology.established(
                connection,
                PeerId::random(),
                None,
                ConnectionDirection::Outbound,
                ConnectionPath::Direct,
            ),
            Err(TopologyError::DuplicateConnectionId)
        );
    }
}
