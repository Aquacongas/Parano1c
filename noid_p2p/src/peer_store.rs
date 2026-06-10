// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Persistent peer store — survives node restarts.
//!
//! On every restart the Kademlia routing table is empty.  If DNS seeds are
//! temporarily unavailable, the node cannot find any peers.  This module
//! writes a cache of recently-seen peers to disk and loads it at startup,
//! so the node can bootstrap from known-good peers without depending on DNS.
//!
//! ## Format
//!
//! A JSON file at `<data_dir>/peers.json`:
//! ```json
//! [
//!   { "peer_id": "12D3KooW...", "addrs": ["/ip4/1.2.3.4/tcp/9400"] },
//!   ...
//! ]
//! ```
//!
//! ## Usage
//!
//! - Load at startup: `PeerStore::load(path)` → add to Kademlia routing table
//! - Save periodically: `PeerStore::save(path, peers)` every 5 minutes
//! - Maximum 500 peers stored (prune oldest on overflow)

use std::path::{Path, PathBuf};
use std::str::FromStr;

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

/// One entry in the peer cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

/// Maximum number of peers to persist.
const MAX_PEERS: usize = 500;

/// Load peers from `<data_dir>/peers.json`.
///
/// Returns a list of `(PeerId, Vec<Multiaddr>)` that can be added directly
/// to the Kademlia routing table.  Invalid entries are silently skipped.
pub fn load(data_dir: &Path) -> Vec<(PeerId, Vec<Multiaddr>)> {
    let path = peer_store_path(data_dir);
    let Ok(bytes) = std::fs::read(&path) else {
        return vec![];
    };
    let Ok(entries) = serde_json::from_slice::<Vec<PeerEntry>>(&bytes) else {
        tracing::warn!(path = %path.display(), "peer store: failed to parse, starting empty");
        return vec![];
    };

    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        let Ok(peer_id) = PeerId::from_str(&entry.peer_id) else {
            continue;
        };
        let addrs: Vec<Multiaddr> = entry.addrs.iter().filter_map(|a| a.parse().ok()).collect();
        if !addrs.is_empty() {
            result.push((peer_id, addrs));
        }
    }

    tracing::debug!(
        path = %path.display(),
        count = result.len(),
        "peer store: loaded"
    );
    result
}

/// Save `peers` to `<data_dir>/peers.json`.
///
/// Prunes to `MAX_PEERS` entries (most recently seen first).
/// Silently ignores write errors — the store is best-effort.
pub fn save(data_dir: &Path, peers: &[(PeerId, Vec<Multiaddr>)]) {
    let path = peer_store_path(data_dir);

    let entries: Vec<PeerEntry> = peers
        .iter()
        .take(MAX_PEERS)
        .map(|(peer_id, addrs)| PeerEntry {
            peer_id: peer_id.to_string(),
            addrs: addrs.iter().map(|a| a.to_string()).collect(),
        })
        .collect();

    match serde_json::to_vec_pretty(&entries) {
        Ok(bytes) => {
            // Write atomically: write to tmp then rename.
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, &bytes).is_ok() {
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    tracing::debug!(err = %e, "peer store: rename failed");
                } else {
                    tracing::debug!(
                        path = %path.display(),
                        count = entries.len(),
                        "peer store: saved"
                    );
                }
            }
        }
        Err(e) => tracing::debug!(err = %e, "peer store: serialise failed"),
    }
}

fn peer_store_path(data_dir: &Path) -> PathBuf {
    data_dir.join("peers.json")
}
