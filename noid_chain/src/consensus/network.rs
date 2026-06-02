// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Network configuration: mainnet / testnet separation.
//!
//! Every network has its own magic bytes, ports, protocol ID, and topics.
//!
//! # Network isolation guarantee
//!
//! libp2p protocol IDs ensure mainnet and testnet nodes NEVER connect:
//!   - Mainnet: `/noid/mainnet/1.0.0`
//!   - Testnet: `/noid/testnet/1.0.0`
//!
//! Gossipsub topic names are network-prefixed for additional isolation.
//!
//! # Ports (no conflicts with Bitcoin 8333/8332, Ethereum 30303/8545, Monero 18080/18081)
//!
//! | Network  | P2P   | RPC   |
//! |----------|-------|-------|
//! | Mainnet  | 9400  | 9401  |
//! | Testnet  | 19400 | 19401 |
//!
//! # Magic bytes
//!
//! | Network  | Magic (ASCII) |
//! |----------|---------------|
//! | Mainnet  | 0x4E4F4944 "NOID" |
//! | Testnet  | 0x544E4F49 "TNOI" |

use std::str::FromStr;

// ---------------------------------------------------------------------------
// NetworkKind
// ---------------------------------------------------------------------------

/// Which network this node participates in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NetworkKind {
    /// Production mainnet. Real NOID, real economic value.
    /// Genesis PoW target: 2^235 (~65K Blake3 hashes on a modern CPU).
    #[default]
    Mainnet,
    /// Public testnet. Test NOID, no real value. Resets periodically.
    /// Easy PoW (2^252) for fast iteration; separate genesis, ports, and P2P.
    Testnet,
}

impl NetworkKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }

    pub fn is_mainnet(&self) -> bool {
        matches!(self, Self::Mainnet)
    }
    pub fn is_testnet(&self) -> bool {
        matches!(self, Self::Testnet)
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
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            other => Err(format!(
                "unknown network '{other}'; expected mainnet or testnet"
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

    /// 4-byte message magic. Prevents cross-network message injection
    /// (gossipsub uses this as part of the message digest).
    pub magic: [u8; 4],

    /// Default P2P listening port.
    pub default_p2p_port: u16,

    /// Default JSON-RPC listening port.
    pub default_rpc_port: u16,

    /// libp2p protocol identifier string.
    /// Nodes refuse connections from peers using a different protocol ID,
    /// providing hard network isolation between mainnet and testnet.
    pub p2p_protocol_id: &'static str,

    /// Gossipsub topic for new block announcements.
    pub topic_blocks: &'static str,

    /// Gossipsub topic for new TxIntent announcements.
    pub topic_txs: &'static str,

    /// DNS seeds for peer discovery (empty on testnet until infra is up).
    pub dns_seeds: &'static [&'static str],
}

impl NetworkConfig {
    pub fn mainnet() -> Self {
        Self {
            kind: NetworkKind::Mainnet,
            magic: [0x4E, 0x4F, 0x49, 0x44], // "NOID"
            default_p2p_port: 9400,
            default_rpc_port: 9401,
            p2p_protocol_id: "/noid/mainnet/1.0.0",
            topic_blocks: "/noid/mainnet/blocks/1",
            topic_txs: "/noid/mainnet/txs/1",
            dns_seeds: &["seed1.noid.network", "seed2.noid.network"],
        }
    }

    pub fn testnet() -> Self {
        Self {
            kind: NetworkKind::Testnet,
            magic: [0x54, 0x4E, 0x4F, 0x49], // "TNOI"
            default_p2p_port: 19400,
            default_rpc_port: 19401,
            p2p_protocol_id: "/noid/testnet/1.0.0",
            topic_blocks: "/noid/testnet/blocks/1",
            topic_txs: "/noid/testnet/txs/1",
            dns_seeds: &["testnet-seed.noid.network"],
        }
    }

    pub fn for_kind(kind: NetworkKind) -> Self {
        match kind {
            NetworkKind::Mainnet => Self::mainnet(),
            NetworkKind::Testnet => Self::testnet(),
        }
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
    fn distinct_magic() {
        assert_ne!(
            NetworkConfig::mainnet().magic,
            NetworkConfig::testnet().magic
        );
    }

    #[test]
    fn distinct_ports() {
        let m = NetworkConfig::mainnet();
        let t = NetworkConfig::testnet();
        assert_ne!(m.default_p2p_port, t.default_p2p_port);
        assert_ne!(m.default_rpc_port, t.default_rpc_port);
    }

    #[test]
    fn distinct_protocol_ids() {
        assert_ne!(
            NetworkConfig::mainnet().p2p_protocol_id,
            NetworkConfig::testnet().p2p_protocol_id,
        );
    }

    #[test]
    fn parse_roundtrip() {
        for s in &["mainnet", "testnet"] {
            let k: NetworkKind = s.parse().unwrap();
            assert_eq!(k.to_string(), *s);
        }
        assert!("devnet".parse::<NetworkKind>().is_err());
        assert!("badnet".parse::<NetworkKind>().is_err());
    }

    #[test]
    fn ports_are_correct() {
        let m = NetworkConfig::mainnet();
        assert_eq!(m.default_p2p_port, 9400);
        assert_eq!(m.default_rpc_port, 9401);
        let t = NetworkConfig::testnet();
        assert_eq!(t.default_p2p_port, 19400);
        assert_eq!(t.default_rpc_port, 19401);
    }
}
