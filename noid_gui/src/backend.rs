// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native GUI boundary around the production node.
//!
//! The GUI never implements consensus, wallet proving, mining, or networking.
//! It supervises the `paranoid` daemon and talks to its loopback JSON-RPC
//! endpoint. This keeps one production path for both headless and graphical
//! users while still allowing the GUI to own the daemon lifecycle.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sysinfo::System;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::model::{
    AddressSnapshot, AppSnapshot, BlockDetailsSnapshot, BlockHeaderSnapshot,
    BlockTransactionInputSnapshot, BlockTransactionOutputSnapshot, BlockTransactionSnapshot,
    ExplorerAddressSnapshot, ExplorerBlockSnapshot, ExplorerSearchResultSnapshot,
    ExplorerSlotSnapshot, ExplorerSnapshot, LogLevel, MatrixClass, MinedBlockSnapshot,
    MinedBlocksSnapshot, MiningSnapshot, NetworkSnapshot, NodeSettingsSnapshot,
    ReceiptDetailSnapshot, ReceiptInputSnapshot, ReceiptOutputSnapshot, ReceiptSnapshot,
    ReceiptSummarySnapshot, ReceiptVerificationSnapshot, ReceiptsSnapshot,
    RecentTransactionSnapshot, RecentTransactionsSnapshot, RetainedBlockSnapshot, SegmentSnapshot,
    SensitiveString, UtxoSnapshot, EXPLORER_PAGE_SIZE, MINED_BLOCK_PAGE_SIZE, RECEIPT_PAGE_SIZE,
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
        let config = self.inner.config.lock().ok();
        formatter
            .debug_struct("Backend")
            .field(
                "rpc_url",
                &config.as_ref().map(|config| config.rpc_url.as_str()),
            )
            .field("mock", &config.as_ref().map(|config| config.mock))
            .finish_non_exhaustive()
    }
}

struct BackendInner {
    config: Mutex<BackendConfig>,
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
    log_level: LogLevel,
    settings_path: PathBuf,
    mock: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedGuiSettings {
    data_dir: PathBuf,
    p2p_listen: String,
    seeds: Vec<String>,
    log_level: LogLevel,
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

#[derive(Debug, Clone)]
pub struct PaymentSubmission {
    pub recipient: String,
    pub txid: String,
    pub amount_micronoid: u64,
    pub fee_micronoid: u64,
    pub input_count: usize,
    pub output_count: usize,
}

#[derive(Debug, Clone)]
pub enum ExplorerLookup {
    Result(ExplorerSearchResultSnapshot),
    Block(BlockDetailsSnapshot),
    Transaction {
        position: u16,
        details: BlockDetailsSnapshot,
    },
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
                config: Mutex::new(config),
            }),
        }
    }

    pub fn is_mock(&self) -> bool {
        self.inner
            .config
            .lock()
            .map(|config| config.mock)
            .unwrap_or(false)
    }

    pub fn wallet_setup_required(&self) -> bool {
        self.inner
            .config
            .lock()
            .map(|config| !config.mock && !config.data_dir.join("wallet.key").exists())
            .unwrap_or(false)
    }

    pub fn settings_snapshot(&self) -> NodeSettingsSnapshot {
        self.inner
            .config
            .lock()
            .map(|config| NodeSettingsSnapshot {
                data_dir: config.data_dir.display().to_string(),
                p2p_listen: config.p2p_listen.clone(),
                custom_seeds: config.seeds.clone(),
                log_level: config.log_level,
            })
            .unwrap_or_else(|_| NodeSettingsSnapshot {
                data_dir: default_data_dir().display().to_string(),
                p2p_listen: DEFAULT_P2P_LISTEN.into(),
                custom_seeds: Vec::new(),
                log_level: LogLevel::Info,
            })
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

    pub async fn apply_settings(&self, settings: NodeSettingsSnapshot) -> Result<(), String> {
        let data_dir = PathBuf::from(settings.data_dir.trim());
        if data_dir.as_os_str().is_empty() {
            return Err("Data directory cannot be empty.".into());
        }
        let p2p_listen = settings.p2p_listen.trim().to_owned();
        if p2p_listen.is_empty()
            || (!p2p_listen.starts_with('/') && p2p_listen.parse::<std::net::SocketAddr>().is_err())
        {
            return Err("P2P listen must be HOST:PORT or a libp2p multiaddr.".into());
        }
        let mut seeds = Vec::new();
        for seed in settings.custom_seeds {
            let seed = seed.trim();
            if seed.is_empty() || seeds.iter().any(|existing| existing == seed) {
                continue;
            }
            if seed.len() > 512 {
                return Err("A custom seed address is too long.".into());
            }
            if seeds.len() >= 32 {
                return Err("At most 32 custom seed peers may be configured.".into());
            }
            seeds.push(seed.to_owned());
        }

        let old_config = self.config_snapshot()?;
        let mut new_config = old_config.clone();
        new_config.data_dir = data_dir;
        new_config.p2p_listen = p2p_listen;
        new_config.seeds = seeds;
        new_config.log_level = settings.log_level;
        if old_config.data_dir == new_config.data_dir
            && old_config.p2p_listen == new_config.p2p_listen
            && old_config.seeds == new_config.seeds
            && old_config.log_level == new_config.log_level
        {
            return Ok(());
        }

        if new_config.mock {
            *self
                .inner
                .config
                .lock()
                .map_err(|_| "GUI settings lock is poisoned".to_string())? = new_config;
            return Ok(());
        }

        let (mode, threads, genesis, owned) = {
            let state = self.lock_supervisor()?;
            (
                state.desired_mode,
                state.selected_threads,
                state.genesis,
                state.owned,
            )
        };
        if !owned {
            return Err("Settings cannot restart an externally managed node.".into());
        }

        persist_gui_settings(&new_config)?;
        if let Err(error) = self.stop_owned().await {
            let _ = persist_gui_settings(&old_config);
            return Err(error);
        }
        *self
            .inner
            .config
            .lock()
            .map_err(|_| "GUI settings lock is poisoned".to_string())? = new_config;
        if let Err(error) = self.spawn(mode, threads, genesis) {
            return match self
                .restore_settings_after_failed_restart(&old_config, mode, threads, genesis)
                .await
            {
                Ok(()) => Err(error),
                Err(restore_error) => Err(format!(
                    "{error}; restoring the previous node settings also failed: {restore_error}"
                )),
            };
        }
        if let Err(error) = self.wait_until_ready().await {
            let _ = self.stop_owned().await;
            return match self
                .restore_settings_after_failed_restart(&old_config, mode, threads, genesis)
                .await
            {
                Ok(()) => Err(error),
                Err(restore_error) => Err(format!(
                    "{error}; restoring the previous node settings also failed: {restore_error}"
                )),
            };
        }
        Ok(())
    }

    pub async fn export_owner_secret(&self) -> Result<SensitiveString, String> {
        if self.is_mock() {
            return Err("Master secret export is unavailable in design preview.".into());
        }
        let config = self.config_snapshot()?;
        let secret = run_wallet_maintenance(&config, "--export-wallet-secret", None).await?;
        if secret.len() != 64 || !secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Node returned an invalid master secret.".into());
        }
        Ok(SensitiveString::new(secret))
    }

    pub async fn import_owner_secret(
        &self,
        master_secret: SensitiveString,
    ) -> Result<String, String> {
        if self.is_mock() {
            return Err("Master secret import is unavailable in design preview.".into());
        }
        let (mode, threads, genesis, owned) = {
            let state = self.lock_supervisor()?;
            (
                state.desired_mode,
                state.selected_threads,
                state.genesis,
                state.owned,
            )
        };
        if !owned {
            return Err("Stop the externally managed node before importing a secret.".into());
        }

        self.stop_owned().await?;
        let config = self.config_snapshot()?;
        let maintenance =
            run_wallet_maintenance(&config, "--import-wallet-secret", Some(master_secret)).await;
        let output = match maintenance {
            Ok(output) => output,
            Err(error) => {
                let restart = match self.spawn(mode, threads, genesis) {
                    Ok(()) => self.wait_until_ready().await,
                    Err(restart_error) => Err(restart_error),
                };
                return match restart {
                    Ok(()) => Err(error),
                    Err(restart_error) => Err(format!(
                        "{error}; restarting the node also failed: {restart_error}"
                    )),
                };
            }
        };
        self.spawn(mode, threads, genesis)?;
        self.wait_until_ready().await?;
        Ok(output)
    }

    pub async fn discover_owner_addresses(&self) -> Result<String, String> {
        if self.is_mock() {
            return Ok("Address discovery is complete.".into());
        }
        let addresses: Vec<WalletAddressInfo> = self
            .rpc_with_timeout(
                "walletDiscoverAddresses",
                json!([20]),
                Duration::from_secs(190),
            )
            .await?;
        let discovered = addresses.len().saturating_sub(1);
        Ok(format!(
            "{discovered} funded address{} discovered.",
            if discovered == 1 { "" } else { "es" }
        ))
    }

    pub async fn generate_owner_secret(&self) -> Result<String, String> {
        let mut secret = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *secret);
        self.import_owner_secret(SensitiveString::new(hex::encode(&*secret)))
            .await?;
        Ok("New master secret generated.".into())
    }

    pub async fn initialize_owner_secret(
        &self,
        master_secret: SensitiveString,
    ) -> Result<String, String> {
        self.install_initial_owner_secret(master_secret).await
    }

    pub async fn initialize_random_owner_secret(&self) -> Result<String, String> {
        let mut secret = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *secret);
        self.install_initial_owner_secret(SensitiveString::new(hex::encode(&*secret)))
            .await
    }

    async fn install_initial_owner_secret(
        &self,
        master_secret: SensitiveString,
    ) -> Result<String, String> {
        if self.is_mock() {
            return Err("Wallet setup is unavailable in design preview.".into());
        }
        let config = self.config_snapshot()?;
        if config.data_dir.join("wallet.key").exists() {
            return Err("The wallet is already initialized.".into());
        }
        if self.ping().await.is_ok() {
            return Err(
                "Stop the node already using this RPC endpoint before wallet setup.".into(),
            );
        }
        {
            let state = self.lock_supervisor()?;
            if state.child.is_some() || state.owned {
                return Err("The local node is already starting.".into());
            }
        }

        let output =
            run_wallet_maintenance(&config, "--import-wallet-secret", Some(master_secret)).await?;
        let (mode, threads, genesis) = {
            let state = self.lock_supervisor()?;
            (state.desired_mode, state.selected_threads, state.genesis)
        };
        self.spawn(mode, threads, genesis)?;
        self.wait_until_ready().await?;
        Ok(output)
    }

    pub async fn prepare_matrix_cache(&self, class: MatrixClass) -> Result<(), String> {
        if self.is_mock() {
            return Ok(());
        }
        let config = self.config_snapshot()?;
        run_node_maintenance(
            &config,
            vec![
                OsString::from("--prepare-history-step-cache"),
                OsString::from(class.cli_value()),
            ],
            None,
        )
        .await?;
        Ok(())
    }

    async fn restore_settings_after_failed_restart(
        &self,
        old_config: &BackendConfig,
        mode: NodeMode,
        threads: usize,
        genesis: bool,
    ) -> Result<(), String> {
        *self
            .inner
            .config
            .lock()
            .map_err(|_| "GUI settings lock is poisoned".to_string())? = old_config.clone();
        let persistence = persist_gui_settings(old_config);
        let restart = match self.spawn(mode, threads, genesis) {
            Ok(()) => self.wait_until_ready().await,
            Err(error) => Err(error),
        };
        match (persistence, restart) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(persist_error), Err(restart_error)) => Err(format!(
                "{persist_error}; restarting the previous node also failed: {restart_error}"
            )),
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
        {
            let mut state = self.lock_supervisor()?;
            state.desired_mode = mode;
            state.selected_threads = selected_threads.clamp(1, available_threads());
            state.genesis = genesis;
        }
        self.spawn(mode, selected_threads, genesis)?;
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

    pub async fn send_payment(
        &self,
        recipient: String,
        amount_micronoid: u64,
    ) -> Result<PaymentSubmission, String> {
        if self.is_mock() {
            return Ok(PaymentSubmission {
                recipient,
                txid: "8f3ca28a5a7191de79dbea850f1679965f43c33c79c557107ec01e04ae45d908".into(),
                amount_micronoid,
                fee_micronoid: 5_800,
                input_count: 1,
                output_count: 2,
            });
        }
        let result = self
            .rpc_with_timeout::<WalletSendResult>(
                "walletSend",
                json!([recipient.clone(), amount_micronoid, 0]),
                Duration::from_secs(120),
            )
            .await?;
        Ok(PaymentSubmission {
            recipient,
            txid: result.txid,
            amount_micronoid: result.amount_micronoid,
            fee_micronoid: result.fee_micronoid,
            input_count: result.input_count,
            output_count: result.output_count,
        })
    }

    pub async fn snapshot(&self, mining_page: u32) -> Result<BackendSnapshot, String> {
        if self.is_mock() {
            let mut snapshot = AppSnapshot::design_preview();
            snapshot.set_preview_mining_page(mining_page);
            return Ok(BackendSnapshot { snapshot });
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
            mined_blocks,
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
            self.rpc::<WalletMinedBlocksPage>(
                "walletMinedBlocks",
                json!([mining_page.max(1), MINED_BLOCK_PAGE_SIZE]),
            ),
        )?;

        let tip_header = self
            .rpc::<Option<BlockHeaderInfo>>("getBlockHeader", json!([chain.height]))
            .await?
            .ok_or_else(|| format!("tip header {} is unavailable", chain.height))?;
        // The genesis timestamp is a protocol constant, not a mined-block
        // observation.  Including the genesis -> height 1 gap makes a fresh
        // network report the time between software genesis and launch instead
        // of its actual block cadence.
        let average_window_start = average_block_time_window_start(chain.height);
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
                    incoming_micronoid: if is_active {
                        balance.pending_incoming_micronoid
                    } else {
                        0
                    },
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
                incoming_micronoid: balance.pending_incoming_micronoid,
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
                ready: node_status.mining_ready,
                isolated: node_status.isolated_mining,
                confirmed_peers: node_status.mining_confirmed_peers,
                required_peers: node_status.mining_required_peers,
                selected_threads,
                available_threads,
            },
            mined_blocks: MinedBlocksSnapshot {
                page: mined_blocks.page,
                total: mined_blocks.total,
                total_pages: mined_blocks.total_pages,
                blocks: mined_blocks
                    .blocks
                    .into_iter()
                    .map(|block| MinedBlockSnapshot {
                        height: block.height,
                        block_hash: block.block_hash,
                        timestamp: block.timestamp,
                        reward_micronoid: block.reward_micronoid,
                        payout_key_index: block.payout_key_index,
                        confirmations: block.confirmations,
                        full_block_available: block.full_block_available,
                    })
                    .collect(),
            },
        };
        Ok(BackendSnapshot { snapshot })
    }

    pub async fn block_details(&self, height: u64) -> Result<BlockDetailsSnapshot, String> {
        if self.is_mock() {
            return Ok(mock_block_details(height));
        }
        let details = self
            .rpc::<Option<RpcBlockDetails>>("getBlockDetails", json!([height]))
            .await?
            .ok_or_else(|| format!("block header {height} is unavailable"))?;
        Ok(details.into_snapshot())
    }

    pub async fn explorer_snapshot(
        &self,
        block_page: u32,
        transaction_page: u32,
    ) -> Result<ExplorerSnapshot, String> {
        if self.is_mock() {
            return Ok(mock_explorer_snapshot(block_page, transaction_page));
        }

        let recent = self
            .rpc::<RpcRecentTransactionsPage>(
                "getRecentTransactions",
                json!([transaction_page.max(1), EXPLORER_PAGE_SIZE, null]),
            )
            .await?
            .into_snapshot();
        let tip_height = recent.tip_height;
        let total_blocks = tip_height.saturating_add(1);
        let block_total_pages = u32::try_from(total_blocks.div_ceil(u64::from(EXPLORER_PAGE_SIZE)))
            .unwrap_or(u32::MAX)
            .max(1);
        let block_page = block_page.max(1).min(block_total_pages);
        let offset =
            u64::from(block_page.saturating_sub(1)).saturating_mul(u64::from(EXPLORER_PAGE_SIZE));
        let first_height = tip_height.saturating_sub(offset);
        let mut blocks = Vec::with_capacity(EXPLORER_PAGE_SIZE as usize);
        for row in 0..EXPLORER_PAGE_SIZE {
            let Some(height) = first_height.checked_sub(u64::from(row)) else {
                break;
            };
            let Some(header) = self
                .rpc::<Option<BlockHeaderInfo>>("getBlockHeader", json!([height]))
                .await?
            else {
                return Err(format!("canonical header {height} is unavailable"));
            };
            let confirmations = tip_height.saturating_sub(height).saturating_add(1);
            blocks.push(ExplorerBlockSnapshot {
                header: header.into_snapshot(),
                confirmations,
                full_block_available: height > 0 && height >= recent.retained_from_height,
            });
        }

        Ok(ExplorerSnapshot {
            tip_height,
            block_page,
            block_total_pages,
            blocks,
            recent_transactions: recent,
        })
    }

    pub async fn explorer_search(
        &self,
        query: String,
        transaction_page: u32,
    ) -> Result<ExplorerLookup, String> {
        if self.is_mock() {
            return mock_explorer_search(&query, transaction_page);
        }

        let query = query.trim();
        if query.is_empty() {
            return Err("Enter an address, block, transaction, or slot.".into());
        }

        if query.to_ascii_lowercase().starts_with("o1") {
            let validated = self
                .rpc::<RpcAddressInfo>("validateAddress", json!([query]))
                .await?;
            if !validated.valid {
                return Err(validated
                    .error
                    .unwrap_or_else(|| "Invalid ParanO(1)d address.".into()));
            }
            let address = validated
                .bech32
                .ok_or_else(|| "validated address has no canonical encoding".to_string())?;
            let slots = self
                .rpc::<Vec<RpcSlotInfo>>("getSlotsByOwner", json!([address.clone()]))
                .await?
                .into_iter()
                .map(RpcSlotInfo::into_snapshot)
                .collect::<Vec<_>>();
            let balance_micronoid = slots
                .iter()
                .map(|slot| u128::from(slot.value_micronoid))
                .sum();
            let recent_transactions = self
                .rpc::<RpcRecentTransactionsPage>(
                    "getRecentTransactions",
                    json!([transaction_page.max(1), EXPLORER_PAGE_SIZE, address.clone()]),
                )
                .await?
                .into_snapshot();
            return Ok(ExplorerLookup::Result(
                ExplorerSearchResultSnapshot::Address(ExplorerAddressSnapshot {
                    address,
                    balance_micronoid,
                    slots,
                    recent_transactions,
                }),
            ));
        }

        let lower = query.to_ascii_lowercase();
        if let Some(raw_slot) = lower.strip_prefix("slot:") {
            let slot_index = raw_slot
                .trim()
                .parse::<u32>()
                .map_err(|_| "Slot query must be written as slot:<number>.".to_string())?;
            let slot = self
                .rpc::<RpcSlotInfo>("getSlot", json!([slot_index]))
                .await?
                .into_snapshot();
            return Ok(ExplorerLookup::Result(ExplorerSearchResultSnapshot::Slot(
                slot,
            )));
        }

        let block_query = lower.strip_prefix("block:").map(str::trim);
        let height_query = query.strip_prefix('#').map(str::trim).or(block_query);
        if let Some(height) = height_query
            .or(Some(query))
            .and_then(|value| value.parse::<u64>().ok())
        {
            return self.block_details(height).await.map(ExplorerLookup::Block);
        }

        let forced_tx = lower.strip_prefix("tx:").map(str::trim);
        let forced_block = lower.strip_prefix("block:").map(str::trim);
        let hash = forced_tx.or(forced_block).unwrap_or(query);
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(
                "Search accepts an o1 address, block height/hash, txid, or slot:<number>.".into(),
            );
        }

        if forced_block.is_none() {
            if let Some(transaction) = self
                .rpc::<Option<RpcTxInfo>>("getTx", json!([hash]))
                .await?
            {
                let position = u16::try_from(transaction.tx_position)
                    .map_err(|_| "transaction position does not fit the explorer".to_string())?;
                let details = self.block_details(transaction.height).await?;
                let retained = details.retained.as_ref().is_some_and(|block| {
                    block
                        .transactions
                        .iter()
                        .any(|candidate| candidate.position == position)
                });
                if retained {
                    return Ok(ExplorerLookup::Transaction { position, details });
                }
                return Err(
                    "Transaction data is outside the 18-block retained window. Verify the payment with its receipt."
                        .into(),
                );
            }
        }

        if forced_tx.is_none() {
            if let Some(header) = self
                .rpc::<Option<BlockHeaderInfo>>("getBlockHeaderByHash", json!([hash]))
                .await?
            {
                return self
                    .block_details(header.height)
                    .await
                    .map(ExplorerLookup::Block);
            }
        }

        Err("No canonical block or transaction matches this hash.".into())
    }

    pub async fn receipts_snapshot(&self, page: u32) -> Result<ReceiptsSnapshot, String> {
        if self.is_mock() {
            return Ok(mock_receipts_snapshot(page));
        }
        Ok(self
            .rpc::<RpcWalletReceiptsPage>("walletReceipts", json!([page.max(1), RECEIPT_PAGE_SIZE]))
            .await?
            .into_snapshot())
    }

    pub async fn receipt_detail(&self, txid: String) -> Result<ReceiptDetailSnapshot, String> {
        if self.is_mock() {
            let receipt_hex = mock_receipt_hex(&txid);
            return Ok(ReceiptDetailSnapshot {
                verification: mock_receipt_verification(&txid),
                receipt_hex,
            });
        }
        let receipt_hex = self
            .rpc::<String>("walletExportReceipt", json!([txid]))
            .await?;
        let verification = self.verify_receipt(receipt_hex.clone()).await?;
        Ok(ReceiptDetailSnapshot {
            receipt_hex,
            verification,
        })
    }

    pub async fn verify_receipt(
        &self,
        receipt_text: String,
    ) -> Result<ReceiptVerificationSnapshot, String> {
        let receipt_hex = normalize_receipt_hex(&receipt_text)?;
        if self.is_mock() {
            return Ok(mock_verify_receipt_hex(&receipt_hex));
        }
        Ok(self
            .rpc::<RpcReceiptVerifyResult>("verifyReceipt", json!([receipt_hex]))
            .await?
            .into_snapshot())
    }

    async fn ping(&self) -> Result<(), String> {
        let _: u64 = self.rpc("blockCount", json!([])).await?;
        Ok(())
    }

    async fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, String> {
        self.rpc_with_timeout(method, params, Duration::from_secs(5))
            .await
    }

    async fn rpc_with_timeout<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<T, String> {
        let id = self.inner.next_request_id.fetch_add(1, Ordering::Relaxed);
        let body = RpcRequest {
            jsonrpc: "2.0",
            id,
            method: format!("paranoid_{method}"),
            params,
        };
        let rpc_url = self.config_snapshot()?.rpc_url;
        let response = self
            .inner
            .client
            .post(rpc_url)
            .json(&body)
            .timeout(timeout)
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
        let config = self.config_snapshot()?;
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
            .arg(config.log_level.as_str())
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
        let config = self.config_snapshot()?;
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
                            config.data_dir.join("paranoid-node.log").display()
                        ));
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!(
            "production node did not open {} within 180 seconds",
            config.rpc_url
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

    fn config_snapshot(&self) -> Result<BackendConfig, String> {
        self.inner
            .config
            .lock()
            .map(|config| config.clone())
            .map_err(|_| "GUI settings lock is poisoned".into())
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
        let settings_path = std::env::var_os("NOID_GUI_SETTINGS_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(default_gui_settings_path);
        let persisted = std::fs::read(&settings_path)
            .ok()
            .filter(|bytes| bytes.len() <= 64 * 1024)
            .and_then(|bytes| serde_json::from_slice::<PersistedGuiSettings>(&bytes).ok());
        let rpc_url = std::env::var("NOID_RPC").unwrap_or_else(|_| DEFAULT_RPC_URL.into());
        let rpc_listen = std::env::var("NOID_GUI_RPC_LISTEN").unwrap_or_else(|_| {
            rpc_listen_from_url(&rpc_url)
                .unwrap_or(DEFAULT_RPC_LISTEN)
                .into()
        });
        let p2p_listen = std::env::var("NOID_GUI_P2P_LISTEN")
            .ok()
            .or_else(|| {
                persisted
                    .as_ref()
                    .map(|settings| settings.p2p_listen.clone())
            })
            .unwrap_or_else(|| DEFAULT_P2P_LISTEN.into());
        let data_dir = std::env::var_os("NOID_GUI_DATA_DIR")
            .map(PathBuf::from)
            .or_else(|| persisted.as_ref().map(|settings| settings.data_dir.clone()))
            .unwrap_or_else(default_data_dir);
        let node_binary = std::env::var_os("NOID_GUI_NODE_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(find_node_binary);
        let seeds = std::env::var("NOID_GUI_SEEDS")
            .ok()
            .map(|seeds| {
                seeds
                    .split(',')
                    .map(str::trim)
                    .filter(|seed| !seed.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .or_else(|| persisted.as_ref().map(|settings| settings.seeds.clone()))
            .unwrap_or_default();
        let log_level = std::env::var("NOID_GUI_LOG")
            .ok()
            .and_then(|level| parse_log_level(&level))
            .or_else(|| persisted.as_ref().map(|settings| settings.log_level))
            .unwrap_or_default();
        let mock = std::env::var("NOID_GUI_MOCK")
            .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
        Self {
            rpc_url,
            rpc_listen,
            p2p_listen,
            data_dir,
            node_binary,
            seeds,
            log_level,
            settings_path,
            mock,
        }
    }
}

fn parse_log_level(value: &str) -> Option<LogLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "error" => Some(LogLevel::Error),
        "warn" => Some(LogLevel::Warn),
        "info" => Some(LogLevel::Info),
        "debug" => Some(LogLevel::Debug),
        _ => None,
    }
}

async fn run_wallet_maintenance(
    config: &BackendConfig,
    operation: &'static str,
    input: Option<SensitiveString>,
) -> Result<String, String> {
    run_node_maintenance(config, vec![OsString::from(operation)], input).await
}

async fn run_node_maintenance(
    config: &BackendConfig,
    arguments: Vec<OsString>,
    input: Option<SensitiveString>,
) -> Result<String, String> {
    let mut command = tokio::process::Command::new(&config.node_binary);
    command
        .arg("--config")
        .arg(config.data_dir.join("paranoid-gui.toml"))
        .arg("--data-dir")
        .arg(&config.data_dir)
        .arg("--log")
        .arg("error")
        .args(arguments)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command.spawn().map_err(|error| {
        format!(
            "run node maintenance with {}: {error}",
            config.node_binary.display()
        )
    })?;
    if let Some(input) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "open node maintenance stdin".to_string())?;
        stdin
            .write_all(input.as_str().as_bytes())
            .await
            .map_err(|error| format!("write node maintenance input: {error}"))?;
        stdin
            .write_all(b"\n")
            .await
            .map_err(|error| format!("finish node maintenance input: {error}"))?;
        stdin
            .shutdown()
            .await
            .map_err(|error| format!("close node maintenance input: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|error| format!("wait for node maintenance: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            format!("Node maintenance operation exited with {}.", output.status)
        } else {
            stderr
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn default_data_dir() -> PathBuf {
    let mut home = home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.push(".paranoid");
    #[cfg(feature = "dev-genesis")]
    home.push("gui-dev");
    home.push("data");
    home
}

fn default_gui_settings_path() -> PathBuf {
    let mut path = home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".paranoid");
    #[cfg(feature = "dev-genesis")]
    path.push("gui-dev");
    path.push("gui-settings.json");
    path
}

fn persist_gui_settings(config: &BackendConfig) -> Result<(), String> {
    let persisted = PersistedGuiSettings {
        data_dir: config.data_dir.clone(),
        p2p_listen: config.p2p_listen.clone(),
        seeds: config.seeds.clone(),
        log_level: config.log_level,
    };
    let bytes = serde_json::to_vec_pretty(&persisted)
        .map_err(|error| format!("encode GUI settings: {error}"))?;
    let parent = config
        .settings_path
        .parent()
        .ok_or_else(|| "GUI settings path has no parent directory".to_string())?;
    std::fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create GUI settings directory {}: {error}",
            parent.display()
        )
    })?;

    let temporary = config.settings_path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|error| {
        format!(
            "create temporary GUI settings {}: {error}",
            temporary.display()
        )
    })?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!(
            "write GUI settings {}: {error}",
            temporary.display()
        ));
    }
    drop(file);

    #[cfg(target_os = "windows")]
    if config.settings_path.exists() {
        std::fs::remove_file(&config.settings_path).map_err(|error| {
            format!(
                "replace GUI settings {}: {error}",
                config.settings_path.display()
            )
        })?;
    }
    if let Err(error) = std::fs::rename(&temporary, &config.settings_path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!(
            "install GUI settings {}: {error}",
            config.settings_path.display()
        ));
    }
    #[cfg(unix)]
    {
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
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

fn average_block_time_window_start(height: u64) -> u64 {
    if height <= 1 {
        height
    } else {
        height.saturating_sub(10).max(1)
    }
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
    mining_ready: bool,
    mining_confirmed_peers: usize,
    mining_required_peers: usize,
    isolated_mining: bool,
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
    hash: String,
    prev_hash: String,
    state_root: String,
    tx_root: String,
    timestamp: u64,
    miner: String,
    nonce_hex: String,
    difficulty_target: String,
    log_slots: u32,
    active_slot_count: u64,
    alloc_counter: u64,
}

impl BlockHeaderInfo {
    fn into_snapshot(self) -> BlockHeaderSnapshot {
        BlockHeaderSnapshot {
            height: self.height,
            hash: self.hash,
            prev_hash: self.prev_hash,
            state_root: self.state_root,
            tx_root: self.tx_root,
            timestamp: self.timestamp,
            miner: self.miner,
            nonce_hex: self.nonce_hex,
            difficulty_target: self.difficulty_target,
            log_slots: self.log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcAddressInfo {
    valid: bool,
    bech32: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcSlotInfo {
    slot_index: u32,
    value: u64,
    creation_id: u64,
    owner: String,
    empty: bool,
}

impl RpcSlotInfo {
    fn into_snapshot(self) -> ExplorerSlotSnapshot {
        ExplorerSlotSnapshot {
            slot_index: self.slot_index,
            value_micronoid: self.value,
            creation_id: self.creation_id,
            owner: self.owner,
            empty: self.empty,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcTxInfo {
    height: u64,
    tx_position: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcRecentTransactionsPage {
    page: u32,
    #[allow(dead_code)]
    page_size: u32,
    total: usize,
    total_pages: u32,
    tip_height: u64,
    retained_from_height: u64,
    transactions: Vec<RpcRecentTransaction>,
}

impl RpcRecentTransactionsPage {
    fn into_snapshot(self) -> RecentTransactionsSnapshot {
        RecentTransactionsSnapshot {
            page: self.page,
            total: self.total,
            total_pages: self.total_pages,
            tip_height: self.tip_height,
            retained_from_height: self.retained_from_height,
            transactions: self
                .transactions
                .into_iter()
                .map(RpcRecentTransaction::into_snapshot)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcRecentTransaction {
    height: u64,
    timestamp: u64,
    position: u16,
    txid: String,
    live_inputs: u16,
    live_outputs: u16,
    fee_micronoid: u64,
    coinbase: bool,
    address_spent_micronoid: Option<String>,
    address_received_micronoid: Option<String>,
}

impl RpcRecentTransaction {
    fn into_snapshot(self) -> RecentTransactionSnapshot {
        RecentTransactionSnapshot {
            height: self.height,
            timestamp: self.timestamp,
            position: self.position,
            txid: self.txid,
            live_inputs: self.live_inputs,
            live_outputs: self.live_outputs,
            fee_micronoid: self.fee_micronoid,
            coinbase: self.coinbase,
            address_spent_micronoid: self.address_spent_micronoid,
            address_received_micronoid: self.address_received_micronoid,
        }
    }
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
    #[serde(default)]
    pending_incoming_micronoid: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletSendResult {
    txid: String,
    amount_micronoid: u64,
    fee_micronoid: u64,
    input_count: usize,
    output_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletUtxoInfo {
    slot_index: u32,
    value_micronoid: u64,
    creation_id: u64,
    #[serde(default)]
    reserved: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct WalletMinedBlocksPage {
    page: u32,
    #[allow(dead_code)]
    page_size: u32,
    total: usize,
    total_pages: u32,
    blocks: Vec<RpcMinedBlock>,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcWalletReceiptsPage {
    page: u32,
    #[allow(dead_code)]
    page_size: u32,
    total: usize,
    total_pages: u32,
    receipts: Vec<RpcWalletReceipt>,
}

impl RpcWalletReceiptsPage {
    fn into_snapshot(self) -> ReceiptsSnapshot {
        ReceiptsSnapshot {
            page: self.page,
            total: self.total,
            total_pages: self.total_pages,
            receipts: self
                .receipts
                .into_iter()
                .map(RpcWalletReceipt::into_snapshot)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcWalletReceipt {
    txid: String,
    height: u64,
    timestamp: u64,
    amount_micronoid: u64,
    fee_micronoid: u64,
    peer_address: Option<String>,
    own_address: Option<String>,
    own_key_index: Option<u32>,
    input_count: usize,
    output_count: usize,
    receipt_bytes: usize,
}

impl RpcWalletReceipt {
    fn into_snapshot(self) -> ReceiptSnapshot {
        ReceiptSnapshot {
            txid: self.txid,
            height: self.height,
            timestamp: self.timestamp,
            amount_micronoid: self.amount_micronoid,
            fee_micronoid: self.fee_micronoid,
            peer_address: self.peer_address,
            own_address: self.own_address,
            own_key_index: self.own_key_index,
            input_count: self.input_count,
            output_count: self.output_count,
            receipt_bytes: self.receipt_bytes,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcReceiptVerifyResult {
    merkle_valid: bool,
    canonical: bool,
    confirmed: bool,
    error: Option<String>,
    authenticated_summary: Option<RpcReceiptSummary>,
}

impl RpcReceiptVerifyResult {
    fn into_snapshot(self) -> ReceiptVerificationSnapshot {
        ReceiptVerificationSnapshot {
            merkle_valid: self.merkle_valid,
            canonical: self.canonical,
            confirmed: self.confirmed,
            error: self.error,
            authenticated_summary: self
                .authenticated_summary
                .map(RpcReceiptSummary::into_snapshot),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcReceiptSummary {
    txid: String,
    claimed_height: u64,
    confirmed_unix: u64,
    tx_index: u16,
    tx_count: u16,
    fee_micronoid: u64,
    inputs: Vec<RpcReceiptInput>,
    outputs: Vec<RpcReceiptOutput>,
}

impl RpcReceiptSummary {
    fn into_snapshot(self) -> ReceiptSummarySnapshot {
        ReceiptSummarySnapshot {
            txid: self.txid,
            claimed_height: self.claimed_height,
            confirmed_unix: self.confirmed_unix,
            tx_index: self.tx_index,
            tx_count: self.tx_count,
            fee_micronoid: self.fee_micronoid,
            inputs: self
                .inputs
                .into_iter()
                .map(|input| ReceiptInputSnapshot {
                    slot_index: input.slot_index,
                    owner: input.owner,
                })
                .collect(),
            outputs: self
                .outputs
                .into_iter()
                .map(|output| ReceiptOutputSnapshot {
                    slot_index: output.slot_index,
                    amount_micronoid: output.amount_micronoid,
                    owner: output.owner,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcReceiptInput {
    slot_index: u32,
    owner: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcReceiptOutput {
    slot_index: u32,
    amount_micronoid: u64,
    owner: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcMinedBlock {
    height: u64,
    block_hash: String,
    #[allow(dead_code)]
    coinbase_txid: String,
    timestamp: u64,
    reward_micronoid: u64,
    #[allow(dead_code)]
    reward_noid: f64,
    #[allow(dead_code)]
    payout_address: String,
    payout_key_index: u32,
    confirmations: u64,
    full_block_available: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcBlockDetails {
    header: BlockHeaderInfo,
    retained: Option<RpcRetainedBlock>,
}

impl RpcBlockDetails {
    fn into_snapshot(self) -> BlockDetailsSnapshot {
        BlockDetailsSnapshot {
            header: self.header.into_snapshot(),
            retained: self.retained.map(RpcRetainedBlock::into_snapshot),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcRetainedBlock {
    proof_class: String,
    logical_transactions: u16,
    user_pages: u16,
    live_inputs: u16,
    live_outputs: u16,
    reward_micronoid: u64,
    #[allow(dead_code)]
    reward_noid: f64,
    total_fees_micronoid: String,
    block_bytes: u64,
    history_step_bytes: u64,
    bundle_bytes: u64,
    transactions: Vec<RpcBlockTransaction>,
}

impl RpcRetainedBlock {
    fn into_snapshot(self) -> RetainedBlockSnapshot {
        RetainedBlockSnapshot {
            proof_class: self.proof_class,
            logical_transactions: self.logical_transactions,
            user_pages: self.user_pages,
            live_inputs: self.live_inputs,
            live_outputs: self.live_outputs,
            reward_micronoid: self.reward_micronoid,
            total_fees_micronoid: self.total_fees_micronoid,
            block_bytes: self.block_bytes,
            history_step_bytes: self.history_step_bytes,
            bundle_bytes: self.bundle_bytes,
            transactions: self
                .transactions
                .into_iter()
                .map(|transaction| BlockTransactionSnapshot {
                    position: transaction.position,
                    txid: transaction.txid,
                    page_count: transaction.page_count,
                    live_inputs: transaction.live_inputs,
                    live_outputs: transaction.live_outputs,
                    fee_micronoid: transaction.fee_micronoid,
                    coinbase: transaction.coinbase,
                    epoch_anchor: transaction.epoch_anchor,
                    input_owner: transaction.input_owner,
                    input_sum_micronoid: transaction.input_sum_micronoid,
                    output_sum_micronoid: transaction.output_sum_micronoid,
                    page_hashes: transaction.page_hashes,
                    inputs: transaction
                        .inputs
                        .into_iter()
                        .map(|input| BlockTransactionInputSnapshot {
                            page: input.page,
                            lane: input.lane,
                            slot_index: input.slot_index,
                            amount_micronoid: input.amount_micronoid,
                            creation_id: input.creation_id,
                        })
                        .collect(),
                    outputs: transaction
                        .outputs
                        .into_iter()
                        .map(|output| BlockTransactionOutputSnapshot {
                            page: output.page,
                            lane: output.lane,
                            slot_index: output.slot_index,
                            amount_micronoid: output.amount_micronoid,
                            owner: output.owner,
                            creation_id: output.creation_id,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RpcBlockTransaction {
    position: u16,
    txid: String,
    page_count: u16,
    live_inputs: u16,
    live_outputs: u16,
    fee_micronoid: u64,
    coinbase: bool,
    epoch_anchor: String,
    input_owner: Option<String>,
    input_sum_micronoid: String,
    output_sum_micronoid: String,
    page_hashes: Vec<String>,
    inputs: Vec<RpcBlockTransactionInput>,
    outputs: Vec<RpcBlockTransactionOutput>,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcBlockTransactionInput {
    page: u16,
    lane: u8,
    slot_index: u32,
    amount_micronoid: u64,
    creation_id: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct RpcBlockTransactionOutput {
    page: u16,
    lane: u8,
    slot_index: u32,
    amount_micronoid: u64,
    owner: String,
    creation_id: u64,
}

fn mock_block_details(height: u64) -> BlockDetailsSnapshot {
    let hash = format!("{:064x}", 0xa94f_2c77_18d9_5063u64.wrapping_add(height));
    let miner = "o1q9p2w4t8k3ux7c5n0r6dmzfae9hj2ls4v8y6c3b7n5q2wk0t9xp";
    let recipient = "o1k3v8s5q2nc7r4m9x6df0wa8h1yt5p3j7u9e2l6b4z8g0cm5nr";
    let coinbase_txid = format!("{:064x}", height.wrapping_mul(3));
    let spend_txid = format!("{:064x}", height.wrapping_mul(5));
    BlockDetailsSnapshot {
        header: BlockHeaderSnapshot {
            height,
            hash,
            prev_hash: format!("{:064x}", height.saturating_sub(1)),
            state_root: format!("{:064x}", height.wrapping_mul(17)),
            tx_root: format!("{:064x}", height.wrapping_mul(31)),
            timestamp: 1_784_732_200,
            miner: miner.into(),
            nonce_hex: "1af0e1d2c3b4a5968778695a4b3c2d1e".into(),
            difficulty_target: "0000000000000000000000000000000000000000000000000000400000000000"
                .into(),
            log_slots: 24,
            active_slot_count: 1_276_944,
            alloc_counter: 1_284_162,
        },
        retained: Some(RetainedBlockSnapshot {
            proof_class: "B64 / m23".into(),
            logical_transactions: 2,
            user_pages: 2,
            live_inputs: 9,
            live_outputs: 5,
            reward_micronoid: 50_018_500,
            total_fees_micronoid: "18500".into(),
            block_bytes: 1_284_096,
            history_step_bytes: 132_640,
            bundle_bytes: 1_416_748,
            transactions: vec![
                BlockTransactionSnapshot {
                    position: 0,
                    txid: coinbase_txid.clone(),
                    page_count: 1,
                    live_inputs: 0,
                    live_outputs: 1,
                    fee_micronoid: 0,
                    coinbase: true,
                    epoch_anchor: format!("{:064x}", 0),
                    input_owner: None,
                    input_sum_micronoid: "0".into(),
                    output_sum_micronoid: "50018500".into(),
                    page_hashes: vec![coinbase_txid],
                    inputs: Vec::new(),
                    outputs: vec![BlockTransactionOutputSnapshot {
                        page: 0,
                        lane: 0,
                        slot_index: 1_284_161,
                        amount_micronoid: 50_018_500,
                        owner: miner.into(),
                        creation_id: (1u64 << 63) | height,
                    }],
                },
                BlockTransactionSnapshot {
                    position: 1,
                    txid: spend_txid,
                    page_count: 2,
                    live_inputs: 9,
                    live_outputs: 4,
                    fee_micronoid: 12_000,
                    coinbase: false,
                    epoch_anchor: format!("{:064x}", height.saturating_sub(1)),
                    input_owner: Some(miner.into()),
                    input_sum_micronoid: "9000000".into(),
                    output_sum_micronoid: "8988000".into(),
                    page_hashes: vec![
                        format!("{:064x}", height.wrapping_mul(7)),
                        format!("{:064x}", height.wrapping_mul(11)),
                    ],
                    inputs: (0..9)
                        .map(|index| BlockTransactionInputSnapshot {
                            page: index / 8,
                            lane: (index % 8) as u8,
                            slot_index: 73 + u32::from(index) * 73,
                            amount_micronoid: 1_000_000,
                            creation_id: 1_284_088 + u64::from(index),
                        })
                        .collect(),
                    outputs: [5_000_000, 2_000_000, 1_000_000, 988_000]
                        .into_iter()
                        .enumerate()
                        .map(|(index, amount)| BlockTransactionOutputSnapshot {
                            page: (index / 2) as u16,
                            lane: (index % 2) as u8,
                            slot_index: 30_000 + index as u32,
                            amount_micronoid: amount,
                            owner: if index == 3 { miner } else { recipient }.into(),
                            creation_id: 1_284_162 + index as u64,
                        })
                        .collect(),
                },
            ],
        }),
    }
}

fn mock_recent_transactions(page: u32, address: Option<&str>) -> RecentTransactionsSnapshot {
    const TIP: u64 = 18_420;
    let retained_from_height = TIP - 17;
    let mut transactions = Vec::new();
    for height in (retained_from_height..=TIP).rev() {
        let details = mock_block_details(height);
        let timestamp = details.header.timestamp.saturating_sub(TIP - height);
        let Some(retained) = details.retained else {
            continue;
        };
        for transaction in retained.transactions {
            let (spent, received) = if let Some(owner) = address {
                let spent = transaction
                    .input_owner
                    .as_deref()
                    .filter(|input_owner| *input_owner == owner)
                    .map(|_| transaction.input_sum_micronoid.clone())
                    .unwrap_or_else(|| "0".into());
                let received = transaction
                    .outputs
                    .iter()
                    .filter(|output| output.owner == owner)
                    .map(|output| u128::from(output.amount_micronoid))
                    .sum::<u128>()
                    .to_string();
                if spent == "0" && received == "0" {
                    continue;
                }
                (Some(spent), Some(received))
            } else {
                (None, None)
            };
            transactions.push(RecentTransactionSnapshot {
                height,
                timestamp,
                position: transaction.position,
                txid: transaction.txid,
                live_inputs: transaction.live_inputs,
                live_outputs: transaction.live_outputs,
                fee_micronoid: transaction.fee_micronoid,
                coinbase: transaction.coinbase,
                address_spent_micronoid: spent,
                address_received_micronoid: received,
            });
        }
    }
    let total = transactions.len();
    let total_pages = if total == 0 {
        0
    } else {
        u32::try_from(total.div_ceil(EXPLORER_PAGE_SIZE as usize)).unwrap_or(u32::MAX)
    };
    let page = if total_pages == 0 {
        1
    } else {
        page.max(1).min(total_pages)
    };
    let offset = page.saturating_sub(1) as usize * EXPLORER_PAGE_SIZE as usize;
    RecentTransactionsSnapshot {
        page,
        total,
        total_pages,
        tip_height: TIP,
        retained_from_height,
        transactions: transactions
            .into_iter()
            .skip(offset)
            .take(EXPLORER_PAGE_SIZE as usize)
            .collect(),
    }
}

fn mock_explorer_snapshot(block_page: u32, transaction_page: u32) -> ExplorerSnapshot {
    const TIP: u64 = 18_420;
    let total_blocks = TIP + 1;
    let block_total_pages =
        u32::try_from(total_blocks.div_ceil(u64::from(EXPLORER_PAGE_SIZE))).unwrap_or(u32::MAX);
    let block_page = block_page.max(1).min(block_total_pages);
    let offset = u64::from(block_page - 1) * u64::from(EXPLORER_PAGE_SIZE);
    let first = TIP.saturating_sub(offset);
    let blocks = (0..EXPLORER_PAGE_SIZE)
        .filter_map(|row| first.checked_sub(u64::from(row)))
        .map(|height| {
            let confirmations = TIP.saturating_sub(height).saturating_add(1);
            ExplorerBlockSnapshot {
                header: mock_block_details(height).header,
                confirmations,
                full_block_available: height > 0 && confirmations <= 18,
            }
        })
        .collect();
    ExplorerSnapshot {
        tip_height: TIP,
        block_page,
        block_total_pages,
        blocks,
        recent_transactions: mock_recent_transactions(transaction_page, None),
    }
}

fn mock_explorer_search(query: &str, transaction_page: u32) -> Result<ExplorerLookup, String> {
    let query = query.trim();
    if query.to_ascii_lowercase().starts_with("o1") {
        let preview = AppSnapshot::design_preview();
        let slots = if preview.active_address().address == query {
            preview
                .utxos
                .into_iter()
                .map(|slot| ExplorerSlotSnapshot {
                    slot_index: slot.slot_index,
                    value_micronoid: slot.value_micronoid,
                    creation_id: slot.creation_id,
                    owner: query.into(),
                    empty: false,
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let balance_micronoid = slots
            .iter()
            .map(|slot| u128::from(slot.value_micronoid))
            .sum();
        return Ok(ExplorerLookup::Result(
            ExplorerSearchResultSnapshot::Address(ExplorerAddressSnapshot {
                address: query.into(),
                balance_micronoid,
                slots,
                recent_transactions: mock_recent_transactions(transaction_page, Some(query)),
            }),
        ));
    }
    if let Some(raw_slot) = query.to_ascii_lowercase().strip_prefix("slot:") {
        let slot_index = raw_slot
            .trim()
            .parse::<u32>()
            .map_err(|_| "Slot query must be written as slot:<number>.".to_string())?;
        return Ok(ExplorerLookup::Result(ExplorerSearchResultSnapshot::Slot(
            ExplorerSlotSnapshot {
                slot_index,
                value_micronoid: 125_000_000,
                creation_id: 1_284_088,
                owner: AppSnapshot::design_preview()
                    .active_address()
                    .address
                    .clone(),
                empty: false,
            },
        )));
    }
    let raw_height = query
        .strip_prefix('#')
        .or_else(|| query.strip_prefix("block:"))
        .unwrap_or(query)
        .trim();
    if let Ok(height) = raw_height.parse::<u64>() {
        return Ok(ExplorerLookup::Block(mock_block_details(height)));
    }
    if query.len() == 64 && query.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let details = mock_block_details(18_420);
        return Ok(ExplorerLookup::Transaction {
            position: 1,
            details,
        });
    }
    Err("Search accepts an o1 address, block height/hash, txid, or slot:<number>.".into())
}

fn normalize_receipt_hex(text: &str) -> Result<String, String> {
    const MAX_RECEIPT_BYTES: usize = 128 * 1024;
    const WHITESPACE_ALLOWANCE: usize = 4 * 1024;
    if text.len() > MAX_RECEIPT_BYTES * 2 + WHITESPACE_ALLOWANCE {
        return Err("Receipt text exceeds the 128 KiB protocol limit.".into());
    }
    let receipt = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if receipt.is_empty() {
        return Err("Paste a receipt before verifying.".into());
    }
    if receipt.len() % 2 != 0 || !receipt.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Receipt must be an even-length hexadecimal string.".into());
    }
    if receipt.len() / 2 > MAX_RECEIPT_BYTES {
        return Err("Receipt exceeds the 128 KiB protocol limit.".into());
    }
    Ok(receipt.to_ascii_lowercase())
}

fn mock_receipt_records() -> Vec<ReceiptSnapshot> {
    const SENDER: &str = "o1q9p2w4t8k3ux7c5n0r6dmzfae9hj2ls4v8y6c3b7n5q2wk0t9xp";
    const RECIPIENTS: [&str; 3] = [
        "o1k3v8s5q2nc7r4m9x6df0wa8h1yt5p3j7u9e2l6b4z8g0cm5nr",
        "o1y7m4h2p8vz5k9c3d6ta0er4wn8qx2f5j7l9s3u6g1b4n8kp2mc",
        "o1mw9w0ak0kexrt8nge0d30wxqe2ghqah5m6fkqjkv3upjwfgpg02stde4s0",
    ];
    (0..12u64)
        .map(|index| ReceiptSnapshot {
            txid: format!(
                "{:064x}",
                0xdb42_2708_9d73_4c1bu64.wrapping_add(index * 0x101)
            ),
            height: 18_418 - index * 9,
            timestamp: 1_784_732_170 - index * 137,
            amount_micronoid: 12_500_000 + index * 750_000,
            fee_micronoid: 9_000 + index * 100,
            peer_address: Some(RECIPIENTS[index as usize % RECIPIENTS.len()].into()),
            own_address: Some(SENDER.into()),
            own_key_index: Some(if index < 8 { 0 } else { 1 }),
            input_count: 1 + index as usize % 4,
            output_count: 2,
            receipt_bytes: 1_146 + index as usize * 64,
        })
        .collect()
}

fn mock_receipts_snapshot(page: u32) -> ReceiptsSnapshot {
    let receipts = mock_receipt_records();
    let total = receipts.len();
    let total_pages = u32::try_from(total.div_ceil(RECEIPT_PAGE_SIZE as usize)).unwrap_or(u32::MAX);
    let page = page.max(1).min(total_pages.max(1));
    let offset = (page - 1) as usize * RECEIPT_PAGE_SIZE as usize;
    ReceiptsSnapshot {
        page,
        total,
        total_pages,
        receipts: receipts
            .into_iter()
            .skip(offset)
            .take(RECEIPT_PAGE_SIZE as usize)
            .collect(),
    }
}

fn mock_receipt_hex(txid: &str) -> String {
    let receipt_bytes = mock_receipt_records()
        .into_iter()
        .find(|receipt| receipt.txid == txid)
        .map_or(1_146, |receipt| receipt.receipt_bytes);
    let mut payload = format!("PARANOID_RECEIPT:{txid}:").into_bytes();
    payload.resize(receipt_bytes, b'0');
    hex::encode(payload)
}

fn mock_verify_receipt_hex(receipt_hex: &str) -> ReceiptVerificationSnapshot {
    let txid = hex::decode(receipt_hex)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| {
            let payload = text.strip_prefix("PARANOID_RECEIPT:")?;
            payload.get(..64).map(str::to_owned)
        });
    txid.as_deref().map_or_else(
        || ReceiptVerificationSnapshot {
            merkle_valid: false,
            canonical: false,
            confirmed: false,
            error: Some("Receipt proof is invalid.".into()),
            authenticated_summary: None,
        },
        mock_receipt_verification,
    )
}

fn mock_receipt_verification(txid: &str) -> ReceiptVerificationSnapshot {
    let Some(receipt) = mock_receipt_records()
        .into_iter()
        .find(|receipt| receipt.txid == txid)
    else {
        return ReceiptVerificationSnapshot {
            merkle_valid: false,
            canonical: false,
            confirmed: false,
            error: Some("Receipt is not part of the preview dataset.".into()),
            authenticated_summary: None,
        };
    };
    let sender = receipt.own_address.clone().unwrap_or_default();
    let recipient = receipt.peer_address.clone().unwrap_or_default();
    ReceiptVerificationSnapshot {
        merkle_valid: true,
        canonical: true,
        confirmed: true,
        error: None,
        authenticated_summary: Some(ReceiptSummarySnapshot {
            txid: receipt.txid,
            claimed_height: receipt.height,
            confirmed_unix: receipt.timestamp,
            tx_index: 1,
            tx_count: 7,
            fee_micronoid: receipt.fee_micronoid,
            inputs: (0..receipt.input_count)
                .map(|index| ReceiptInputSnapshot {
                    slot_index: 9_693_928 + index as u32 * 73,
                    owner: sender.clone(),
                })
                .collect(),
            outputs: vec![
                ReceiptOutputSnapshot {
                    slot_index: 9_728_645,
                    amount_micronoid: receipt.amount_micronoid,
                    owner: recipient,
                },
                ReceiptOutputSnapshot {
                    slot_index: 9_728_646,
                    amount_micronoid: 37_491_000,
                    owner: sender,
                },
            ],
        }),
    }
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

    #[test]
    fn average_block_time_window_never_uses_genesis_as_a_sample() {
        assert_eq!(average_block_time_window_start(0), 0);
        assert_eq!(average_block_time_window_start(1), 1);
        assert_eq!(average_block_time_window_start(2), 1);
        assert_eq!(average_block_time_window_start(11), 1);
        assert_eq!(average_block_time_window_start(12), 2);
    }

    #[test]
    fn receipt_text_normalization_accepts_transport_whitespace_only() {
        assert_eq!(normalize_receipt_hex(" AA bb\n01 ").unwrap(), "aabb01");
        assert!(normalize_receipt_hex("").is_err());
        assert!(normalize_receipt_hex("abc").is_err());
        assert!(normalize_receipt_hex("aa:bb").is_err());
    }

    #[test]
    fn gui_node_settings_round_trip_through_owner_only_file() {
        let directory = tempfile::tempdir().unwrap();
        let settings_path = directory.path().join("gui-settings.json");
        let config = BackendConfig {
            rpc_url: DEFAULT_RPC_URL.into(),
            rpc_listen: DEFAULT_RPC_LISTEN.into(),
            p2p_listen: "127.0.0.1:19400".into(),
            data_dir: directory.path().join("node-data"),
            node_binary: PathBuf::from("paranoid"),
            seeds: vec!["seed-a.example:9400".into(), "dnsaddr:noid.network".into()],
            log_level: LogLevel::Debug,
            settings_path: settings_path.clone(),
            mock: false,
        };

        persist_gui_settings(&config).unwrap();
        let decoded: PersistedGuiSettings =
            serde_json::from_slice(&std::fs::read(&settings_path).unwrap()).unwrap();
        assert_eq!(decoded.data_dir, config.data_dir);
        assert_eq!(decoded.p2p_listen, config.p2p_listen);
        assert_eq!(decoded.seeds, config.seeds);
        assert_eq!(decoded.log_level, LogLevel::Debug);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(settings_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
