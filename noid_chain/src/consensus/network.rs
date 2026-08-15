// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Network configuration for the public v2 testnet.
//!
//! Every network participant shares these magic bytes, ports, protocol ID,
//! and gossipsub topics. libp2p protocol IDs prevent cross-network connections.
//!
//! # Ports (no conflicts with Bitcoin 8333/8332, Ethereum 30303/8545, Monero 18080/18081)
//!
//! | Network  | P2P   | RPC   |
//! |----------|-------|-------|
//! | Testnet  | 9500  | 9501  |
//!
//! # Magic bytes
//!
//! | Network  | Magic (ASCII) |
//! |----------|---------------|
//! | Testnet  | 0x4E4F4954 "NOIT" |

use std::str::FromStr;

// ---------------------------------------------------------------------------
// NetworkKind
// ---------------------------------------------------------------------------

/// Which network this node participates in.
///
/// Only the public testnet is supported by this release. Attempting to parse
/// any other string returns
/// an error at startup so misconfigured nodes fail fast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NetworkKind {
    /// Public testnet. Balances and rewards have no mainnet value.
    #[default]
    Testnet,
}

impl NetworkKind {
    pub fn as_str(&self) -> &'static str {
        "testnet"
    }

    pub fn is_mainnet(&self) -> bool {
        false
    }
}

impl std::fmt::Display for NetworkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NetworkKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "testnet" => Ok(Self::Testnet),
            other => Err(format!(
                "unknown network '{other}'; only 'testnet' is supported"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// NetworkConfig
// ---------------------------------------------------------------------------

/// All network-specific runtime constants.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub kind: NetworkKind,

    /// 4-byte message magic. Prevents cross-network message injection.
    pub magic: [u8; 4],

    /// Default P2P listening port.
    pub default_p2p_port: u16,

    /// Default JSON-RPC listening port.
    pub default_rpc_port: u16,

    /// libp2p protocol identifier string.
    /// Nodes refuse connections from peers using a different protocol ID.
    pub p2p_protocol_id: &'static str,

    /// Gossipsub topic for new block announcements.
    pub topic_blocks: &'static str,

    /// Gossipsub topic for new TxIntent announcements.
    pub topic_txs: &'static str,

    /// DNS seeds for peer discovery.
    pub dns_seeds: &'static [&'static str],
}

impl NetworkConfig {
    pub fn testnet() -> Self {
        Self {
            kind: NetworkKind::Testnet,
            magic: [0x4E, 0x4F, 0x49, 0x54], // "NOIT"
            default_p2p_port: 9500,
            default_rpc_port: 9501,
            // The v2 public testnet is intentionally isolated from every
            // withdrawn launch binary and from the future mainnet. The exact
            // authenticated profile handshake adds a second fail-closed gate.
            p2p_protocol_id: "/noid/testnet/530016417023d5e9/1",
            topic_blocks: "/noid/testnet/530016417023d5e9/blocks/1",
            topic_txs: "/noid/testnet/530016417023d5e9/txs/1",
            // DNS seeds — two formats supported:
            //
            // 1. Bare hostname  → dialled as /dns4/<host>/tcp/9500
            //    Simple A-record setup.  Works immediately once the domain
            //    points to a live node.  No PeerID verification.
            //
            // 2. "dnsaddr:<hostname>" → dialled as /dnsaddr/<hostname>
            //    Resolves _dnsaddr.<hostname> TXT records.  Each TXT entry
            //    encodes a full multiaddr including PeerID, e.g.:
            //      _dnsaddr.parano1d.org TXT
            //        "dnsaddr=/ip4/1.2.3.4/tcp/9500/p2p/12D3KooW..."
            //    Connection is cryptographically verified against PeerID.
            //    This is the libp2p standard (used by IPFS, Filecoin).
            //    Add one TXT record per seed node; DNS round-robins them.
            //
            // Keep one individual A-record hostname per planned seed as well.
            // Each hostname creates an independent startup dial; unresolved
            // future seeds fail independently without delaying usable seeds.
            dns_seeds: &[
                "seed1.parano1d.org",
                "seed2.parano1d.org",
                "seed3.parano1d.org",
                "seed4.parano1d.org",
            ],
        }
    }

    pub fn for_kind(_kind: NetworkKind) -> Self {
        Self::testnet()
    }

    /// Default P2P listen address as a libp2p multiaddr string.
    pub fn default_p2p_listen(&self) -> String {
        format!("/ip4/0.0.0.0/tcp/{}", self.default_p2p_port)
    }

    /// Default RPC listen address.
    pub fn default_rpc_listen(&self) -> String {
        format!("127.0.0.1:{}", self.default_rpc_port)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_magic_is_noit() {
        assert_eq!(NetworkConfig::testnet().magic, [0x4E, 0x4F, 0x49, 0x54]);
    }

    #[test]
    fn testnet_ports() {
        let m = NetworkConfig::testnet();
        assert_eq!(m.default_p2p_port, 9500);
        assert_eq!(m.default_rpc_port, 9501);
    }

    #[test]
    fn testnet_protocol_id() {
        let testnet = NetworkConfig::testnet();
        assert_eq!(testnet.p2p_protocol_id, "/noid/testnet/530016417023d5e9/1");
        assert_eq!(
            testnet.topic_blocks,
            "/noid/testnet/530016417023d5e9/blocks/1"
        );
        assert_eq!(testnet.topic_txs, "/noid/testnet/530016417023d5e9/txs/1");
    }

    #[test]
    fn testnet_has_live_individual_dns_seeds() {
        assert_eq!(
            NetworkConfig::testnet().dns_seeds,
            &[
                "seed1.parano1d.org",
                "seed2.parano1d.org",
                "seed3.parano1d.org",
                "seed4.parano1d.org",
            ]
        );
    }

    #[test]
    fn parse_testnet() {
        let k: NetworkKind = "testnet".parse().unwrap();
        assert_eq!(k.to_string(), "testnet");
        assert!(!k.is_mainnet());
    }

    #[test]
    fn parse_unknown_fails() {
        assert!("devnet".parse::<NetworkKind>().is_err());
        assert!("mainnet".parse::<NetworkKind>().is_err());
    }
}
