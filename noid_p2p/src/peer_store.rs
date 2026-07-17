// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Persistent cache of successful public outbound peers.
//!
//! The cache is an availability hint, never an authority. Only peers reached
//! through a successful outbound connection are recorded; inbound identities
//! cannot poison the next restart merely by filling Kademlia buckets. Startup
//! anchors are randomized and selected from distinct public network groups.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::{Multiaddr, PeerId};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::peer_diversity::{contains_public_ip, public_network_group, PublicNetworkGroup};

const MAX_PEERS: usize = 500;
const MAX_ADDRS_PER_PEER: usize = 8;
pub(crate) const MAX_STARTUP_ANCHORS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerEntry {
    peer_id: String,
    addrs: Vec<String>,
    /// Missing in the legacy format. A zero timestamp remains usable but loses
    /// eviction priority to a peer confirmed by the current implementation.
    #[serde(default)]
    last_success_unix: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct CachedPeer {
    pub(crate) peer_id: PeerId,
    pub(crate) addrs: Vec<Multiaddr>,
    last_success_unix: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SuccessfulPeerCache {
    entries: HashMap<PeerId, CachedPeer>,
}

impl SuccessfulPeerCache {
    pub(crate) fn entries(&self) -> impl Iterator<Item = &CachedPeer> {
        self.entries.values()
    }

    pub(crate) fn record_success(&mut self, peer_id: PeerId, addr: Multiaddr) {
        if !contains_public_ip(&addr) {
            return;
        }
        let now = unix_now();
        let entry = self.entries.entry(peer_id).or_insert_with(|| CachedPeer {
            peer_id,
            addrs: Vec::new(),
            last_success_unix: now,
        });
        entry.last_success_unix = now;
        if !entry.addrs.contains(&addr) {
            if entry.addrs.len() == MAX_ADDRS_PER_PEER {
                entry.addrs.remove(0);
            }
            entry.addrs.push(addr);
        }
        self.prune();
    }

    /// A cold restart should not deterministically contact the same peers, and
    /// one hosting provider must not occupy every anchor attempt.
    pub(crate) fn randomized_startup_anchors(&self) -> Vec<CachedPeer> {
        let mut candidates: Vec<_> = self.entries.values().cloned().collect();
        candidates.shuffle(&mut rand::thread_rng());
        let mut groups = HashSet::<PublicNetworkGroup>::new();
        let mut selected = Vec::with_capacity(MAX_STARTUP_ANCHORS);
        for mut candidate in candidates {
            candidate.addrs.shuffle(&mut rand::thread_rng());
            let Some(group) = candidate.addrs.iter().find_map(public_network_group) else {
                continue;
            };
            if groups.insert(group) {
                selected.push(candidate);
                if selected.len() == MAX_STARTUP_ANCHORS {
                    break;
                }
            }
        }
        selected
    }

    fn prune(&mut self) {
        while self.entries.len() > MAX_PEERS {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_success_unix)
                .map(|(peer, _)| *peer)
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

pub(crate) fn load(data_dir: &Path) -> SuccessfulPeerCache {
    let path = peer_store_path(data_dir);
    let Ok(bytes) = std::fs::read(&path) else {
        return SuccessfulPeerCache::default();
    };
    let Ok(mut entries) = serde_json::from_slice::<Vec<PeerEntry>>(&bytes) else {
        tracing::warn!(path = %path.display(), "peer store: failed to parse, starting empty");
        return SuccessfulPeerCache::default();
    };
    entries.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.last_success_unix));

    let mut cache = SuccessfulPeerCache::default();
    for entry in entries.into_iter().take(MAX_PEERS) {
        let Ok(peer_id) = PeerId::from_str(&entry.peer_id) else {
            continue;
        };
        let mut seen = HashSet::new();
        let addrs: Vec<Multiaddr> = entry
            .addrs
            .iter()
            .filter_map(|encoded| encoded.parse().ok())
            .filter(|addr| contains_public_ip(addr))
            .filter(|addr| seen.insert(addr.clone()))
            .take(MAX_ADDRS_PER_PEER)
            .collect();
        if addrs.is_empty() || cache.entries.contains_key(&peer_id) {
            continue;
        }
        cache.entries.insert(
            peer_id,
            CachedPeer {
                peer_id,
                addrs,
                last_success_unix: entry.last_success_unix,
            },
        );
    }

    tracing::debug!(
        path = %path.display(),
        count = cache.entries.len(),
        "peer store: loaded successful outbound peers"
    );
    cache
}

pub(crate) fn save(data_dir: &Path, cache: &SuccessfulPeerCache) {
    let path = peer_store_path(data_dir);
    let mut peers: Vec<_> = cache.entries.values().collect();
    peers.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.last_success_unix));
    let entries: Vec<PeerEntry> = peers
        .into_iter()
        .take(MAX_PEERS)
        .map(|entry| PeerEntry {
            peer_id: entry.peer_id.to_string(),
            addrs: entry.addrs.iter().map(ToString::to_string).collect(),
            last_success_unix: entry.last_success_unix,
        })
        .collect();

    match serde_json::to_vec_pretty(&entries) {
        Ok(bytes) => {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, &bytes).is_ok() {
                if let Err(error) = std::fs::rename(&tmp, &path) {
                    tracing::debug!(err = %error, "peer store: rename failed");
                } else {
                    tracing::debug!(
                        path = %path.display(),
                        count = entries.len(),
                        "peer store: saved successful outbound peers"
                    );
                }
            }
        }
        Err(error) => tracing::debug!(err = %error, "peer store: serialise failed"),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn peer_store_path(data_dir: &Path) -> PathBuf {
    data_dir.join("peers.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_addr(ip: &str) -> Multiaddr {
        format!("/ip4/{ip}/tcp/9400").parse().unwrap()
    }

    #[test]
    fn inbound_or_private_addresses_never_enter_success_cache() {
        let mut cache = SuccessfulPeerCache::default();
        let peer = PeerId::random();
        cache.record_success(peer, "/ip4/127.0.0.1/tcp/9400".parse().unwrap());
        cache.record_success(peer, "/ip4/10.0.0.1/tcp/9400".parse().unwrap());
        assert_eq!(cache.entries().count(), 0);
        cache.record_success(peer, public_addr("8.8.8.8"));
        assert_eq!(cache.entries().count(), 1);
    }

    #[test]
    fn startup_anchors_have_distinct_groups() {
        let mut cache = SuccessfulPeerCache::default();
        for ip in ["8.8.1.1", "8.8.2.2", "9.9.1.1", "11.1.1.1"] {
            cache.record_success(PeerId::random(), public_addr(ip));
        }
        let anchors = cache.randomized_startup_anchors();
        let groups: HashSet<_> = anchors
            .iter()
            .flat_map(|entry| entry.addrs.iter().find_map(public_network_group))
            .collect();
        assert_eq!(anchors.len(), 3);
        assert_eq!(groups.len(), anchors.len());
    }

    #[test]
    fn legacy_store_is_filtered_bounded_and_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let peer = PeerId::random();
        let legacy = serde_json::json!([{
            "peer_id": peer.to_string(),
            "addrs": [
                "/ip4/127.0.0.1/tcp/9400",
                "/ip4/8.8.8.8/tcp/9400",
                "/ip4/8.8.8.8/tcp/9400"
            ]
        }]);
        std::fs::write(
            peer_store_path(dir.path()),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();

        let cache = load(dir.path());
        let loaded = cache.entries().next().unwrap();
        assert_eq!(loaded.peer_id, peer);
        assert_eq!(loaded.addrs, vec![public_addr("8.8.8.8")]);
        save(dir.path(), &cache);
        let persisted: Vec<PeerEntry> =
            serde_json::from_slice(&std::fs::read(peer_store_path(dir.path())).unwrap()).unwrap();
        assert_eq!(persisted[0].last_success_unix, 0);
    }
}
