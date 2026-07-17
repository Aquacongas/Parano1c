// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Small, transport-level neighbour diversity policy.
//!
//! A `PeerId` proves key continuity, not operator diversity: one host can mint
//! arbitrarily many identities.  Public automatic outbound connections are
//! therefore spread across coarse network groups (IPv4 /16, IPv6 /32), while
//! inbound fan-in is bounded both per address and per group.  Private/LAN
//! addresses are deliberately outside this policy so local clusters and
//! multiple nodes behind a development NAT remain usable.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libp2p::{multiaddr::Protocol, swarm::ConnectionId, Multiaddr, PeerId};

// Bitcoin Core uses distinct automatic outbound netgroups, while production
// Ethereum clients tolerate several co-located peers. Two paths per coarse
// group preserve provider/NAT usability without letting one cheap prefix fill
// a 64-connection outbound budget.
const MAX_PUBLIC_OUTBOUND_PEERS_PER_GROUP: usize = 2;
const MAX_PUBLIC_INBOUND_PEERS_PER_IP: usize = 8;
const MAX_PUBLIC_INBOUND_PEERS_PER_GROUP: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PublicNetworkGroup {
    Ipv4([u8; 2]),
    Ipv6([u8; 4]),
}

impl PublicNetworkGroup {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                Self::Ipv4([octets[0], octets[1]])
            }
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                Self::Ipv6([octets[0], octets[1], octets[2], octets[3]])
            }
        }
    }
}

pub(crate) fn public_network_group(addr: &Multiaddr) -> Option<PublicNetworkGroup> {
    public_ip(addr).map(PublicNetworkGroup::from_ip)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiversityRejection {
    OutboundGroupFull { group: PublicNetworkGroup },
    InboundIpFull { ip: IpAddr },
    InboundGroupFull { group: PublicNetworkGroup },
}

#[derive(Clone, Copy, Debug)]
enum TrackedDirection {
    Outbound,
    Inbound,
}

#[derive(Clone, Copy, Debug)]
struct TrackedConnection {
    peer: PeerId,
    ip: IpAddr,
    group: PublicNetworkGroup,
    direction: TrackedDirection,
}

/// Tracks admitted public connections so limits are released exactly when the
/// corresponding libp2p connection closes.
#[derive(Default)]
pub(crate) struct PeerDiversity {
    // `None` records an admitted LAN/private connection. Keeping it here lets
    // the close path distinguish a deliberately rejected public connection
    // (which must not emit a phantom PeerDisconnected event).
    connections: HashMap<ConnectionId, Option<TrackedConnection>>,
    outbound_groups: HashMap<PublicNetworkGroup, HashMap<PeerId, usize>>,
    inbound_ips: HashMap<IpAddr, HashMap<PeerId, usize>>,
    inbound_groups: HashMap<PublicNetworkGroup, HashMap<PeerId, usize>>,
}

impl PeerDiversity {
    pub(crate) fn try_admit(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        remote_addr: &Multiaddr,
        outbound: bool,
    ) -> Result<(), DiversityRejection> {
        let Some(ip) = public_ip(remote_addr) else {
            // Local/private transports are useful for LAN discovery and test
            // clusters. They cannot consume public network-group diversity.
            self.connections.insert(connection_id, None);
            return Ok(());
        };
        let group = PublicNetworkGroup::from_ip(ip);

        if outbound {
            if distinct_peer_count(&self.outbound_groups, &group, peer)
                >= MAX_PUBLIC_OUTBOUND_PEERS_PER_GROUP
            {
                return Err(DiversityRejection::OutboundGroupFull { group });
            }
        } else {
            if distinct_peer_count(&self.inbound_ips, &ip, peer) >= MAX_PUBLIC_INBOUND_PEERS_PER_IP
            {
                return Err(DiversityRejection::InboundIpFull { ip });
            }
            if distinct_peer_count(&self.inbound_groups, &group, peer)
                >= MAX_PUBLIC_INBOUND_PEERS_PER_GROUP
            {
                return Err(DiversityRejection::InboundGroupFull { group });
            }
        }

        let direction = if outbound {
            increment_peer_count(&mut self.outbound_groups, group, peer);
            TrackedDirection::Outbound
        } else {
            increment_peer_count(&mut self.inbound_ips, ip, peer);
            increment_peer_count(&mut self.inbound_groups, group, peer);
            TrackedDirection::Inbound
        };
        let previous = self.connections.insert(
            connection_id,
            Some(TrackedConnection {
                peer,
                ip,
                group,
                direction,
            }),
        );
        debug_assert!(previous.is_none(), "libp2p connection IDs are unique");
        Ok(())
    }

    pub(crate) fn remove(&mut self, connection_id: ConnectionId) -> bool {
        let Some(connection) = self.connections.remove(&connection_id) else {
            return false;
        };
        let Some(connection) = connection else {
            return true;
        };
        match connection.direction {
            TrackedDirection::Outbound => {
                decrement_peer_count(&mut self.outbound_groups, connection.group, connection.peer);
            }
            TrackedDirection::Inbound => {
                decrement_peer_count(&mut self.inbound_ips, connection.ip, connection.peer);
                decrement_peer_count(&mut self.inbound_groups, connection.group, connection.peer);
            }
        }
        true
    }
}

fn distinct_peer_count<K: Eq + std::hash::Hash>(
    groups: &HashMap<K, HashMap<PeerId, usize>>,
    key: &K,
    candidate: PeerId,
) -> usize {
    groups.get(key).map_or(0, |peers| {
        peers.len() - usize::from(peers.contains_key(&candidate))
    })
}

fn increment_peer_count<K: Eq + std::hash::Hash>(
    groups: &mut HashMap<K, HashMap<PeerId, usize>>,
    key: K,
    peer: PeerId,
) {
    *groups.entry(key).or_default().entry(peer).or_default() += 1;
}

fn decrement_peer_count<K: Eq + std::hash::Hash>(
    groups: &mut HashMap<K, HashMap<PeerId, usize>>,
    key: K,
    peer: PeerId,
) {
    let remove_group = if let Some(peers) = groups.get_mut(&key) {
        if let Some(count) = peers.get_mut(&peer) {
            *count -= 1;
            if *count == 0 {
                peers.remove(&peer);
            }
        }
        peers.is_empty()
    } else {
        false
    };
    if remove_group {
        groups.remove(&key);
    }
}

/// Returns the first globally-routable IP in a transport address. DNS is
/// resolved by libp2p before the underlying TCP dial, so successful public
/// connection endpoints normally contain the resolved IP.
pub(crate) fn public_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) if is_public_ipv4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) if is_public_ipv6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

pub(crate) fn contains_public_ip(addr: &Multiaddr) -> bool {
    public_ip(addr).is_some()
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    let global_unicast = octets[0] & 0xe0 == 0x20;
    let documentation = octets[0..4] == [0x20, 0x01, 0x0d, 0xb8];
    global_unicast && !documentation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(value: &str) -> Multiaddr {
        value.parse().unwrap()
    }

    #[test]
    fn public_network_groups_are_coarse_and_non_public_addresses_are_exempt() {
        assert_eq!(
            public_ip(&addr("/ip4/8.8.4.4/tcp/9400")).map(PublicNetworkGroup::from_ip),
            Some(PublicNetworkGroup::Ipv4([8, 8]))
        );
        assert_eq!(
            public_ip(&addr("/ip6/2606:4700:4700::1111/tcp/9400")).map(PublicNetworkGroup::from_ip),
            Some(PublicNetworkGroup::Ipv6([0x26, 0x06, 0x47, 0x00]))
        );
        for non_public in [
            "/ip4/127.0.0.1/tcp/9400",
            "/ip4/10.1.2.3/tcp/9400",
            "/ip4/192.0.2.1/tcp/9400",
            "/ip6/::1/tcp/9400",
            "/ip6/fd00::1/tcp/9400",
            "/ip6/2001:db8::1/tcp/9400",
        ] {
            assert_eq!(public_ip(&addr(non_public)), None, "{non_public}");
        }
    }

    #[test]
    fn outbound_admission_requires_distinct_public_groups_but_allows_second_path() {
        let mut diversity = PeerDiversity::default();
        let first = PeerId::random();
        let second = PeerId::random();
        let third = PeerId::random();
        let id1 = ConnectionId::new_unchecked(1);
        let id2 = ConnectionId::new_unchecked(2);
        let id3 = ConnectionId::new_unchecked(3);
        let id4 = ConnectionId::new_unchecked(4);
        let id5 = ConnectionId::new_unchecked(5);

        diversity
            .try_admit(id1, first, &addr("/ip4/8.8.1.1/tcp/9400"), true)
            .unwrap();
        diversity
            .try_admit(id2, first, &addr("/ip4/8.8.2.2/tcp/9400"), true)
            .expect("direct plus relay path for one identity stays usable");
        diversity
            .try_admit(id3, second, &addr("/ip4/8.8.3.3/tcp/9400"), true)
            .expect("a second identity in one provider group is tolerated");
        assert!(matches!(
            diversity.try_admit(id4, third, &addr("/ip4/8.8.4.4/tcp/9400"), true),
            Err(DiversityRejection::OutboundGroupFull { .. })
        ));
        diversity
            .try_admit(id4, third, &addr("/ip4/9.9.3.3/tcp/9400"), true)
            .expect("a distinct /16 is independent");

        diversity.remove(id1);
        assert!(matches!(
            diversity.try_admit(id5, third, &addr("/ip4/8.8.5.5/tcp/9400"), true),
            Err(DiversityRejection::OutboundGroupFull { .. })
        ));
        diversity.remove(id2);
        diversity
            .try_admit(id5, third, &addr("/ip4/8.8.5.5/tcp/9400"), true)
            .expect("the group is released after the final path closes");
    }

    #[test]
    fn inbound_admission_bounds_peer_ids_from_one_public_ip() {
        let mut diversity = PeerDiversity::default();
        let public = addr("/ip4/8.8.8.8/tcp/50000");
        for id in 0..MAX_PUBLIC_INBOUND_PEERS_PER_IP {
            diversity
                .try_admit(
                    ConnectionId::new_unchecked(id),
                    PeerId::random(),
                    &public,
                    false,
                )
                .unwrap();
        }
        assert!(matches!(
            diversity.try_admit(
                ConnectionId::new_unchecked(100),
                PeerId::random(),
                &public,
                false,
            ),
            Err(DiversityRejection::InboundIpFull { .. })
        ));
    }
}
