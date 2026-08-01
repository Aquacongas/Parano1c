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
    /// CLI flag: --p2p-listen HOST:PORT  (e.g. 0.0.0.0:9400)
    /// Defaults to the compiled network's P2P port (9400 on mainnet).
    pub listen: Option<String>,
    /// Bootstrap seed peers.
    /// Config file: list of HOST:PORT strings (e.g. ["1.2.3.4:9400"]).
    /// CLI flag: --seed HOST:PORT  (repeat for multiple seeds).
    pub seeds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend: "mdbx" or "ram".
    pub backend: String,
    /// Data directory override. Default: ~/.parano1d/data.
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RpcConfig {
    /// JSON-RPC listen address.
    /// Defaults to the compiled network's local RPC address
    /// (127.0.0.1:9401 on mainnet).
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MiningConfig {
    /// Enable built-in miner.
    pub enabled: bool,
    /// Miner coinbase address (bech32m). Empty = current active wallet address.
    pub miner_address: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                listen: None, // determined by --network at runtime
                seeds: vec![],
            },
            storage: StorageConfig {
                backend: "mdbx".into(),
                path: PathBuf::from("~/.parano1d/data"), // sentinel — overridden by network
            },
            rpc: RpcConfig {
                listen: None, // determined by --network at runtime
            },
            mining: MiningConfig::default(),
        }
    }
}
