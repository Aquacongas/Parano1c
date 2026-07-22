// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native GUI boundary around the production node.
//!
//! The GUI never implements consensus, wallet proving, mining, or networking.
//! It supervises the `paranoid` daemon and talks to its loopback JSON-RPC
//! endpoint. This keeps one production path for both headless and graphical
//! users while still allowing the GUI to own the daemon lifecycle.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sysinfo::System;

use crate::model::{
    AddressSnapshot, AppSnapshot, MiningSnapshot, NetworkSnapshot, SegmentSnapshot, UtxoSnapshot,
};

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:9401";
const DEFAULT_RPC_LISTEN: &str = "127.0.0.1:9401";
const DEFAULT_P2P_LISTEN: &str = "0.0.0.0:9400";
const STATE_SEGMENT_LOG: u32 = 16;
const STATE_MAP_BUCKETS: usize = 256;
const GENESIS_DIFFICULTY_LOG2: f64 = 238.0;

#[derive(Clone)]
pub struct Backend {
    inner: Arc<BackendInner>,
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Backend")
            .field("rpc_url", &self.inner.config.rpc_url)
            .field("mock", &self.inner.config.mock)
            .finish_non_exhaustive()
    }
}

struct BackendInner {
    config: BackendConfig,
    client: Client,
    next_request_id: AtomicU64,
    supervisor: Mutex<SupervisorState>,
    system: Mutex<System>,
}

impl Drop for BackendInner {
    fn drop(&mut self) {
        let Ok(mut supervisor) = self.supervisor.lock() else {
            return;
        };
        if supervisor.owned {
            if let Some(child) = supervisor.child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[derive(Debug, Clone)]
struct BackendConfig {
    rpc_url: String,
    rpc_listen: String,
    p2p_listen: String,
    data_dir: PathBuf,
    node_binary: PathBuf,
    seeds: Vec<String>,
    mock: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    Node,
    Miner,
}

impl NodeMode {
    fn cli_value(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Miner => "miner",
        }
    }
}

#[derive(Debug)]
struct SupervisorState {
    child: Option<Child>,
    owned: bool,
    desired_mode: NodeMode,
    selected_threads: usize,
    genesis: bool,
}

#[derive(Debug, Clone)]
pub struct BackendSnapshot {
    pub snapshot: AppSnapshot,
}

impl Backend {
    pub fn from_env() -> Self {
        let config = BackendConfig::from_env();
        let available_threads = available_threads();
        Self {
            inner: Arc::new(BackendInner {
                client: Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .expect("build loopback RPC client"),
                next_request_id: AtomicU64::new(1),
                supervisor: Mutex::new(SupervisorState {
                    child: None,
                    owned: false,
                    desired_mode: NodeMode::Node,
                    selected_threads: available_threads,
                    genesis: false,
                }),
                system: Mutex::new(System::new_all()),
                config,
            }),
        }
    }

    pub fn is_mock(&self) -> bool {
        self.inner.config.mock
    }

    pub fn available_threads(&self) -> usize {
        available_threads()
    }

    pub fn selected_threads(&self) -> usize {
        self.inner
            .supervisor
            .lock()
            .map(|state| state.selected_threads)
            .unwrap_or_else(|_| available_threads())
    }

    pub fn set_selected_threads(&self, threads: usize) {
        if let Ok(mut state) = self.inner.supervisor.lock() {
            state.selected_threads = threads.clamp(1, available_threads());
        }
    }

    pub async fn ensure_running(&self) -> Result<(), String> {
        if self.is_mock() || self.ping().await.is_ok() {
            return Ok(());
        }

        let (mode, threads, genesis, has_live_child) = {
            let mut state = self.lock_supervisor()?;
            let has_live_child = match state.child.as_mut() {
                Some(child) => match child.try_wait() {
                    Ok(None) => true,
                    Ok(Some(_)) | Err(_) => {
                        state.child = None;
                        state.owned = false;
                        false
                    }
                },
                None => false,
            };
            (
                state.desired_mode,
                state.selected_threads,
                state.genesis,
                has_live_child,
            )
        };

        if !has_live_child {
            self.spawn(mode, threads, genesis)?;
        }
        self.wait_until_ready().await
    }

    pub async fn restart(
        &self,
        mode: NodeMode,
        selected_threads: usize,
        genesis: bool,
    ) -> Result<(), String> {
        if self.is_mock() {
            let mut state = self.lock_supervisor()?;
            state.desired_mode = mode;
            state.selected_threads = selected_threads.clamp(1, available_threads());
            state.genesis = genesis;
            return Ok(());
        }

        {
            let state = self.lock_supervisor()?;
            if !state.owned {
                return Err(
                    "The connected daemon is externally managed; stop it before changing GUI mining mode"
                        .into(),
                );
            }
        }

        self.stop_owned().await?;
        let effective_genesis = {
            let mut state = self.lock_supervisor()?;
            state.desired_mode = mode;
            state.selected_threads = selected_threads.clamp(1, available_threads());
            state.genesis |= genesis;
            state.genesis
        };
        self.spawn(mode, selected_threads, effective_genesis)?;
        self.wait_until_ready().await
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        if self.is_mock() {
            return Ok(());
        }
        let owned = self.lock_supervisor()?.owned;
        if owned {
            self.stop_owned().await
        } else {
            Ok(())
        }
    }

    pub async fn set_active_address(&self, key_index: u32) -> Result<(), String> {
        if self.is_mock() {
            return Ok(());
        }
        let _: WalletAddressInfo = self
            .rpc("walletSetActiveAddress", json!([key_index]))
            .await?;
        Ok(())
    }

    pub async fn create_address(&self) -> Result<(), String> {
        if self.is_mock() {
            return Ok(());
        }
        let _: WalletAddressInfo = self.rpc("walletNextAddress", json!([])).await?;
        Ok(())
    }

    pub async fn snapshot(&self) -> Result<BackendSnapshot, String> {
        if self.is_mock() {
            return Ok(BackendSnapshot {
                snapshot: AppSnapshot::design_preview(),
            });
        }

        let (
            chain,
            state,
            state_map,
            mining,
            node_status,
            peers,
            mempool,
            addresses,
            active_address,
            balance,
            wallet_utxos,
        ) = tokio::try_join!(
            self.rpc::<ChainInfo>("getChainInfo", json!([])),
            self.rpc::<StateInfo>("getStateInfo", json!([])),
            self.rpc::<StateMapInfo>("getStateMap", json!([])),
            self.rpc::<MiningInfo>("getMiningInfo", json!([])),
            self.rpc::<NodeStatus>("getNodeStatus", json!([])),
            self.rpc::<usize>("getPeerCount", json!([])),
            self.rpc::<MempoolStats>("getMempoolStats", json!([])),
            self.rpc::<Vec<WalletAddressInfo>>("walletListAddresses", json!([])),
            self.rpc::<WalletAddressInfo>("walletActiveAddress", json!([])),
            self.rpc::<WalletBalance>("walletGetBalance", json!([])),
            self.rpc::<Vec<WalletUtxoInfo>>("walletListUtxos", json!([])),
        )?;

        let tip_header = self
            .rpc::<Option<BlockHeaderInfo>>("getBlockHeader", json!([chain.height]))
            .await?
            .ok_or_else(|| format!("tip header {} is unavailable", chain.height))?;
        let average_window_start = chain.height.saturating_sub(10);
        let average_start_header = if average_window_start == chain.height {
            tip_header.clone()
        } else {
            self.rpc::<Option<BlockHeaderInfo>>("getBlockHeader", json!([average_window_start]))
                .await?
                .unwrap_or_else(|| tip_header.clone())
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let block_span = chain.height.saturating_sub(average_start_header.height);
        let average_block_time_ms = tip_header
            .timestamp
            .saturating_sub(average_start_header.timestamp)
            .saturating_mul(1_000)
            .checked_div(block_span)
            .unwrap_or(15_000);
        let (cpu_load, memory_used_bytes, memory_total_bytes) = self.system_metrics();
        let mining_enabled = node_status.mining;
        let selected_threads = if mining_enabled {
            node_status.worker_threads
        } else {
            self.selected_threads()
                .min(node_status.available_threads.max(1))
        };
        let available_threads = node_status.available_threads.max(1);

        let mut address_snapshots = addresses
            .into_iter()
            .map(|address| {
                let is_active = address.key_index == active_address.key_index || address.is_active;
                AddressSnapshot {
                    key_index: address.key_index,
                    address: address.address,
                    label: if address.key_index == 0 {
                        "Main".into()
                    } else {
                        format!("Address {}", address.key_index)
                    },
                    balance_micronoid: if is_active {
                        balance.balance_micronoid
                    } else {
                        0
                    },
                    utxo_count: if is_active { balance.utxo_count } else { 0 },
                    reserved_utxo_count: if is_active {
                        wallet_utxos.iter().filter(|utxo| utxo.reserved).count()
                    } else {
                        0
                    },
                    pending_outbound_micronoid: if is_active {
                        balance.pending_outbound_micronoid
                    } else {
                        0
                    },
                    incoming_micronoid: 0,
                }
            })
            .collect::<Vec<_>>();
        if address_snapshots.is_empty() {
            address_snapshots.push(AddressSnapshot {
                key_index: active_address.key_index,
                address: active_address.address.clone(),
                label: "Main".into(),
                balance_micronoid: balance.balance_micronoid,
                utxo_count: balance.utxo_count,
                reserved_utxo_count: wallet_utxos.iter().filter(|utxo| utxo.reserved).count(),
                pending_outbound_micronoid: balance.pending_outbound_micronoid,
                incoming_micronoid: 0,
            });
        }
        let active_position = address_snapshots
            .iter()
            .position(|address| address.key_index == active_address.key_index)
            .unwrap_or(0);

        let domain_segments = 1usize
            .checked_shl(chain.log_slots.saturating_sub(STATE_SEGMENT_LOG))
            .unwrap_or(STATE_MAP_BUCKETS)
            .max(1);
        let map_bucket_count = state_map.live_counts.len().clamp(1, STATE_MAP_BUCKETS);
        let mut owned_buckets = HashSet::new();
        let utxos = wallet_utxos
            .into_iter()
            .map(|utxo| {
                let segment_id = (utxo.slot_index as usize) >> STATE_SEGMENT_LOG;
                let bucket = segment_id
                    .saturating_mul(map_bucket_count)
                    .checked_div(domain_segments)
                    .unwrap_or(0)
                    .min(map_bucket_count - 1) as u8;
                owned_buckets.insert(bucket);
                UtxoSnapshot {
                    slot_index: utxo.slot_index,
                    value_micronoid: utxo.value_micronoid,
                    creation_id: utxo.creation_id,
                    segment: bucket,
                    reserved: utxo.reserved,
                }
            })
            .collect::<Vec<_>>();
        let max_bucket_live = state_map
            .live_counts
            .iter()
            .copied()
            .max()
            .unwrap_or(0)
            .max(1);
        let segments = state_map
            .live_counts
            .iter()
            .take(STATE_MAP_BUCKETS)
            .enumerate()
            .map(|(bucket, live_count)| SegmentSnapshot {
                // The top meter carries absolute state use. The atlas carries
                // spatial density, so retain the absolute signal while also
                // normalising sparse early states against their busiest cell.
                occupancy: ((*live_count as f32 / state_map.bucket_capacity.max(1) as f32).sqrt())
                    .max(*live_count as f32 / max_bucket_live as f32),
                owned: owned_buckets.contains(&(bucket as u8)),
            })
            .collect();

        let snapshot = AppSnapshot {
            network: NetworkSnapshot {
                height: chain.height,
                peers,
                active_slots: state.active_slots,
                log_slots: state.log_slots,
                mempool_transactions: mempool.size,
                mempool_capacity_transactions: mempool.capacity.max(1),
                mempool_bytes: mempool.intent_bytes,
                mempool_capacity_bytes: mempool.max_intent_bytes.max(1),
                cpu_load,
                memory_used_bytes,
                memory_total_bytes,
                last_block_age_seconds: now.saturating_sub(tip_header.timestamp),
                average_block_time_ms,
                difficulty: target_difficulty(&mining.difficulty_target),
                backend: node_status.backend.to_ascii_uppercase(),
                synced: node_status.synced,
                // Reaching this snapshot means the production node accepted
                // the canonical tip and its exact state transition proof.
                terminal_verified: true,
                state_root: tip_header.state_root,
            },
            addresses: address_snapshots,
            active_address: active_position,
            segments,
            utxos,
            mining: MiningSnapshot {
                enabled: mining_enabled,
                selected_threads,
                available_threads,
            },
        };
        Ok(BackendSnapshot { snapshot })
    }

    async fn ping(&self) -> Result<(), String> {
        let _: u64 = self.rpc("blockCount", json!([])).await?;
        Ok(())
    }

    async fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, String> {
        let id = self.inner.next_request_id.fetch_add(1, Ordering::Relaxed);
        let body = RpcRequest {
            jsonrpc: "2.0",
            id,
            method: format!("paranoid_{method}"),
            params,
        };
        let response = self
            .inner
            .client
            .post(&self.inner.config.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|error| format!("local node RPC: {error}"))?;
        let status = response.status();
        let response = response
            .json::<RpcResponse>()
            .await
            .map_err(|error| format!("decode local node RPC response: {error}"))?;
        if let Some(error) = response.error {
            return Err(format!("{} ({})", error.message, error.code));
        }
        if !status.is_success() {
            return Err(format!("local node RPC returned HTTP {status}"));
        }
        serde_json::from_value(response.result)
            .map_err(|error| format!("decode local node RPC {method} result: {error}"))
    }

    fn spawn(&self, mode: NodeMode, selected_threads: usize, genesis: bool) -> Result<(), String> {
        let config = &self.inner.config;
        std::fs::create_dir_all(&config.data_dir).map_err(|error| {
            format!(
                "create GUI node data directory {}: {error}",
                config.data_dir.display()
            )
        })?;
        let config_path = config.data_dir.join("paranoid-gui.toml");
        let log_path = config.data_dir.join("paranoid-node.log");
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|error| format!("open node log {}: {error}", log_path.display()))?;
        let log_error = log
            .try_clone()
            .map_err(|error| format!("clone node log handle: {error}"))?;

        let mut command = Command::new(&config.node_binary);
        command
            .arg("--config")
            .arg(config_path)
            .arg("--data-dir")
            .arg(&config.data_dir)
            .arg("--p2p-listen")
            .arg(&config.p2p_listen)
            .arg("--rpc-listen")
            .arg(&config.rpc_listen)
            .arg("--mode")
            .arg(mode.cli_value())
            .arg("--log")
            .arg("info")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_error))
            .env("NO_COLOR", "1");
        if mode == NodeMode::Miner {
            command
                .arg("--cpu-threads")
                .arg(selected_threads.clamp(1, available_threads()).to_string());
        }
        if genesis {
            command.arg("--genesis");
        }
        for seed in &config.seeds {
            command.arg("--seed").arg(seed);
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }

        let child = command.spawn().map_err(|error| {
            format!(
                "start production node {}: {error}",
                config.node_binary.display()
            )
        })?;
        let mut state = self.lock_supervisor()?;
        state.child = Some(child);
        state.owned = true;
        state.desired_mode = mode;
        state.selected_threads = selected_threads.clamp(1, available_threads());
        state.genesis = genesis;
        Ok(())
    }

    async fn wait_until_ready(&self) -> Result<(), String> {
        for _ in 0..360 {
            if self.ping().await.is_ok() {
                return Ok(());
            }
            {
                let mut state = self.lock_supervisor()?;
                if let Some(child) = state.child.as_mut() {
                    if let Some(status) = child
                        .try_wait()
                        .map_err(|error| format!("inspect node process: {error}"))?
                    {
                        state.child = None;
                        state.owned = false;
                        return Err(format!(
                            "production node exited with {status}; see {}",
                            self.inner
                                .config
                                .data_dir
                                .join("paranoid-node.log")
                                .display()
                        ));
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!(
            "production node did not open {} within 180 seconds",
            self.inner.config.rpc_url
        ))
    }

    async fn stop_owned(&self) -> Result<(), String> {
        let owned = self.lock_supervisor()?.owned;
        if !owned {
            return Ok(());
        }

        let _ = self.rpc::<String>("stop", json!([])).await;
        // A miner may be sealing an atomic HistoryStep when stop arrives.
        // Give one normal block interval plus headroom before the GUI falls
        // back to process termination.
        for _ in 0..300 {
            let exited = {
                let mut state = self.lock_supervisor()?;
                match state.child.as_mut() {
                    None => true,
                    Some(child) => match child.try_wait() {
                        Ok(Some(_)) => {
                            state.child = None;
                            state.owned = false;
                            true
                        }
                        Ok(None) => false,
                        Err(error) => return Err(format!("inspect node shutdown: {error}")),
                    },
                }
            };
            if exited {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let mut state = self.lock_supervisor()?;
        if let Some(child) = state.child.as_mut() {
            child
                .kill()
                .map_err(|error| format!("force-stop node after shutdown timeout: {error}"))?;
            let _ = child.wait();
        }
        state.child = None;
        state.owned = false;
        Ok(())
    }

    fn lock_supervisor(&self) -> Result<std::sync::MutexGuard<'_, SupervisorState>, String> {
        self.inner
            .supervisor
            .lock()
            .map_err(|_| "GUI node supervisor lock is poisoned".into())
    }

    fn system_metrics(&self) -> (f32, u64, u64) {
        let Ok(mut system) = self.inner.system.lock() else {
            return (0.0, 0, 1);
        };
        system.refresh_cpu_usage();
        system.refresh_memory();
        (
            (system.global_cpu_usage() / 100.0).clamp(0.0, 1.0),
            system.used_memory(),
            system.total_memory().max(1),
        )
    }
}

impl BackendConfig {
    fn from_env() -> Self {
        let rpc_url = std::env::var("NOID_RPC").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
        let rpc_listen = std::env::var("NOID_GUI_RPC_LISTEN").unwrap_or_else(|_| {
            rpc_listen_from_url(&rpc_url)
                .unwrap_or(DEFAULT_RPC_LISTEN)
                .into()
        });
        let p2p_listen =
            std::env::var("NOID_GUI_P2P_LISTEN").unwrap_or_else(|_| DEFAULT_P2P_LISTEN.into());
        let data_dir = std::env::var_os("NOID_GUI_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(default_data_dir);
        let node_binary = std::env::var_os("NOID_GUI_NODE_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(find_node_binary);
        let seeds = std::env::var("NOID_GUI_SEEDS")
            .ok()
            .into_iter()
            .flat_map(|seeds| {
                seeds
                    .split(',')
                    .map(str::trim)
                    .filter(|seed| !seed.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect();
        let mock = std::env::var("NOID_GUI_MOCK")
            .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
        Self {
            rpc_url,
            rpc_listen,
            p2p_listen,
            data_dir,
            node_binary,
            seeds,
            mock,
        }
    }
}

fn default_data_dir() -> PathBuf {
    let mut home = home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.push(".paranoid");
    #[cfg(feature = "dev-genesis")]
    home.push("gui-dev");
    home.push("data");
    home
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            let mut home = PathBuf::from(drive);
            home.push(path);
            Some(home)
        })
}

fn find_node_binary() -> PathBuf {
    let executable_name = if cfg!(target_os = "windows") {
        "paranoid.exe"
    } else {
        "paranoid"
    };
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            let sibling = parent.join(executable_name);
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from(executable_name)
}

fn rpc_listen_from_url(url: &str) -> Option<&str> {
    url.strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .map(|authority| authority.split('/').next().unwrap_or(authority))
}

fn available_threads() -> usize {
    std::thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(1)
        .max(1)
}

fn target_difficulty(target_hex: &str) -> f64 {
    let Ok(bytes) = hex::decode(target_hex) else {
        return 1.0;
    };
    let Some((index, byte)) = bytes
        .iter()
        .copied()
        .enumerate()
        .rev()
        .find(|(_, byte)| *byte != 0)
    else {
        return f64::INFINITY;
    };
    let target_log2 = index as f64 * 8.0 + f64::from(byte).log2();
    2.0_f64.powf(GENESIS_DIFFICULTY_LOG2 - target_log2).max(1.0)
}

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    params: Value,
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Value,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ChainInfo {
    height: u64,
    #[allow(dead_code)]
    best_hash: String,
    #[allow(dead_code)]
    difficulty_target: String,
    #[allow(dead_code)]
    active_slot_count: u64,
    log_slots: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct StateInfo {
    log_slots: u32,
    #[allow(dead_code)]
    capacity: u64,
    active_slots: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct StateMapInfo {
    #[allow(dead_code)]
    log_slots: u32,
    bucket_capacity: u64,
    live_counts: Vec<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct MiningInfo {
    #[allow(dead_code)]
    height: u64,
    #[allow(dead_code)]
    difficulty_bits: u32,
    difficulty_target: String,
}

#[derive(Debug, Clone, Deserialize)]
struct NodeStatus {
    synced: bool,
    mining: bool,
    backend: String,
    available_threads: usize,
    worker_threads: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct MempoolStats {
    size: usize,
    capacity: usize,
    intent_bytes: u64,
    max_intent_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct BlockHeaderInfo {
    height: u64,
    state_root: String,
    timestamp: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletAddressInfo {
    address: String,
    key_index: u32,
    is_active: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletBalance {
    balance_micronoid: u64,
    utxo_count: usize,
    pending_outbound_micronoid: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletUtxoInfo {
    slot_index: u32,
    value_micronoid: u64,
    creation_id: u64,
    #[serde(default)]
    reserved: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_difficulty_is_relative_to_the_genesis_floor() {
        let mut genesis = [0u8; 32];
        genesis[29] = 0x40;
        assert!((target_difficulty(&hex::encode(genesis)) - 1.0).abs() < f64::EPSILON);

        let mut twice_as_hard = genesis;
        twice_as_hard[29] = 0x20;
        assert!((target_difficulty(&hex::encode(twice_as_hard)) - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn loopback_rpc_url_yields_a_daemon_listen_address() {
        assert_eq!(
            rpc_listen_from_url("http://127.0.0.1:9401"),
            Some("127.0.0.1:9401")
        );
        assert_eq!(
            rpc_listen_from_url("http://127.0.0.1:9411/rpc"),
            Some("127.0.0.1:9411")
        );
    }
}
