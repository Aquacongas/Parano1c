// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

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
    /// P2P listen address.
    /// Config file: HOST:PORT or libp2p multiaddr ("/ip4/...").
    /// CLI flag: --p2p-listen HOST:PORT  (e.g. 0.0.0.0:9301)
    /// Defaults to network-specific port (9301 mainnet, 19301 testnet).
    pub listen: Option<String>,
    /// Bootstrap seed peers.
    /// Config file: list of HOST:PORT strings (e.g. ["1.2.3.4:9301"]).
    /// CLI flag: --seed HOST:PORT  (repeat for multiple seeds).
    pub seeds: Vec<String>,
    /// Maximum connected peers. Default: 50.
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
    /// Internal PoW mining threads. 0 = balanced default (roughly half of available cores).
    pub mining_threads: usize,
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
