// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Node configuration (parsed from TOML file or CLI flags).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub rpc: RpcConfig,
    pub mining: MiningConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    /// libp2p listen multiaddr.
    /// Defaults to network-specific port (9400 mainnet, 19400 testnet).
    pub listen: Option<String>,
    /// Bootstrap seed nodes (in addition to DNS seeds).
    pub seeds: Vec<String>,
    /// Maximum peers. Default: 50.
    pub max_peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend: "mdbx" or "ram".
    pub backend: String,
    /// Data directory override. Default: ~/.noid/<network>/data.
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RpcConfig {
    /// JSON-RPC listen address.
    /// Defaults to network-specific port (9401 mainnet, 19401 testnet).
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiningConfig {
    /// Enable built-in miner.
    pub enabled: bool,
    /// PoW threads. 0 = all physical cores.
    pub threads: usize,
    /// Miner coinbase address (32-byte hex). Empty = burn address [0;32].
    pub miner_address: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                listen: None, // determined by --network at runtime
                seeds: vec![],
                max_peers: 50,
            },
            storage: StorageConfig {
                backend: "mdbx".into(),
                path: PathBuf::from("~/.paranoid/data"), // sentinel — overridden by network
            },
            rpc: RpcConfig {
                listen: None, // determined by --network at runtime
            },
            mining: MiningConfig::default(),
        }
    }
}
