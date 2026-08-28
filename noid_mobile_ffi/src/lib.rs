// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! JNI bridge for the Parano1d Android full node.
//!
//! Kotlin never touches chain/wallet internals directly.
//! All long-running Rust operations execute on one process-wide Tokio runtime.

#[cfg(target_os = "android")]
fn android_boot_log(message: impl AsRef<str>) {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    const ANDROID_LOG_INFO: c_int = 4;

    let Ok(tag) = CString::new("NOID_BOOT") else {
        return;
    };

    let message = message.as_ref().replace('\0', "?");

    let Ok(text) = CString::new(message) else {
        return;
    };

    unsafe {
        __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
#[inline]
fn android_boot_log(_message: impl AsRef<str>) {}

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use jni::{
    objects::{JClass, JString},
    sys::{jint, jlong, jstring},
    JNIEnv,
};
use once_cell::sync::Lazy;
use serde::Serialize;

use noid_mobile_node::MobileNodeRuntime;

// ==========================================================================
// Global async runtime
// ==========================================================================

static TOKIO: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("parano1d-mobile")
        .build()
        .expect("create mobile Tokio runtime")
});

// ==========================================================================
// Global node state
// ==========================================================================

struct RunningNode {
    node: Arc<MobileNodeRuntime>,
    p2p: Option<noid_mobile_node::MobileP2PHandle>,
}

static NODE: Lazy<Mutex<Option<RunningNode>>> = Lazy::new(|| Mutex::new(None));

// ==========================================================================
// JSON result types
// ==========================================================================

#[derive(Serialize)]
struct BasicResult {
    ok: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct WalletPresenceResult {
    ok: bool,
    configured: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct ExportWalletResult {
    ok: bool,
    master_key: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct NodeStatusResult {
    ok: bool,
    running: bool,

    tip_height: u64,
    tip_hash: String,

    peers: usize,

    syncing: bool,

    sync_state: String,
    history_step_ready: bool,

    error: Option<String>,
}

#[derive(Serialize)]
struct WalletInfoResult {
    ok: bool,

    address: Option<String>,

    balance_micronoid: u64,

    error: Option<String>,
}

#[derive(Serialize)]
struct SendResult {
    ok: bool,

    txid: Option<String>,

    amount_micronoid: u64,

    fee_micronoid: u64,

    input_count: usize,

    output_count: usize,

    error: Option<String>,
}

#[derive(Serialize)]
struct RecentTransactionJson {
    txid: String,
    direction: &'static str,
    amount_micronoid: u64,
    height: u64,
    timestamp: u64,
    pending: bool,
    is_coinbase: bool,
}

#[derive(Serialize)]
struct RecentTransactionsResult {
    ok: bool,
    transactions: Vec<RecentTransactionJson>,
    error: Option<String>,
}

// ==========================================================================
// helpers
// ==========================================================================

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|error| {
        format!(
            r#"{{"ok":false,"error":"JSON serialization failed: {}"}}"#,
            error
        )
    })
}

fn java_string(env: &mut JNIEnv, value: String) -> jstring {
    match env.new_string(value) {
        Ok(value) => value.into_raw(),

        Err(_) => std::ptr::null_mut(),
    }
}

fn get_string(env: &mut JNIEnv, value: &JString) -> Result<String> {
    Ok(env.get_string(value).context("read Java string")?.into())
}

fn with_node<T>(f: impl FnOnce(&RunningNode) -> Result<T>) -> Result<T> {
    let guard = NODE
        .lock()
        .map_err(|_| anyhow::anyhow!("mobile node state lock poisoned"))?;

    let node = guard.as_ref().context("mobile node is not running")?;

    f(node)
}

// ==========================================================================
// START
//
// At this exact stage this starts the complete durable Rust backend:
//
// MDBX
// wallet
// mempool
// HeaderDag
// HistoryStep runtime
//
// P2P is attached in the next Kotlin/network config bridge once the selected
// network configuration is supplied.
// ==========================================================================

fn mainnet_seed_multiaddr(seed: &str, default_port: u16) -> anyhow::Result<libp2p::Multiaddr> {
    use anyhow::Context as _;
    use std::net::IpAddr;

    let seed = seed.trim();

    if seed.is_empty() {
        anyhow::bail!("empty mainnet seed");
    }

    // Already a complete multiaddr.
    if seed.starts_with('/') {
        return seed
            .parse::<libp2p::Multiaddr>()
            .with_context(|| format!("parse mainnet seed multiaddr {seed:?}"));
    }

    // Raw IP address.
    if let Ok(ip) = seed.parse::<IpAddr>() {
        let addr = match ip {
            IpAddr::V4(ip) => {
                format!("/ip4/{ip}/tcp/{default_port}")
            }
            IpAddr::V6(ip) => {
                format!("/ip6/{ip}/tcp/{default_port}")
            }
        };

        return addr
            .parse::<libp2p::Multiaddr>()
            .with_context(|| format!("parse mainnet IP seed {seed:?}"));
    }

    // DNS bootstrap hostname.
    format!("/dns/{seed}/tcp/{default_port}")
        .parse::<libp2p::Multiaddr>()
        .with_context(|| format!("parse mainnet DNS seed {seed:?}"))
}

fn mainnet_p2p_config() -> anyhow::Result<noid_mobile_node::MobileP2PConfig> {
    use anyhow::Context as _;
    use std::collections::HashSet;
    use std::net::{IpAddr, ToSocketAddrs};

    let net = noid_chain::consensus::NetworkConfig::mainnet();

    let listen_addr = "/ip4/0.0.0.0/tcp/0"
        .parse::<libp2p::Multiaddr>()
        .context("parse mobile P2P listen address")?;

    let topics = noid_p2p::protocol::NetworkTopics::for_network_cfg(&net);

    let mut seeds = Vec::new();

    let mut seen = HashSet::new();

    for seed in net.dns_seeds {
        let seed = seed.trim();

        if seed.is_empty() {
            continue;
        }

        let target = format!("{}:{}", seed, net.default_p2p_port);

        let mut native_resolved = false;

        match target.to_socket_addrs() {
            Ok(addresses) => {
                for socket in addresses {
                    let text = match socket.ip() {
                        IpAddr::V4(ip) => {
                            format!("/ip4/{}/tcp/{}", ip, socket.port())
                        }

                        IpAddr::V6(ip) => {
                            format!("/ip6/{}/tcp/{}", ip, socket.port())
                        }
                    };

                    let addr = text
                        .parse::<libp2p::Multiaddr>()
                        .with_context(|| format!("parse resolved mobile seed {}", socket))?;

                    if seen.insert(addr.to_string()) {
                        tracing::info!(
                            seed = %seed,
                            addr = %addr,
                            "mobile mainnet seed resolved"
                        );

                        seeds.push(addr);
                    }

                    native_resolved = true;
                }
            }

            Err(error) => {
                tracing::warn!(
                    seed = %seed,
                    %error,
                    "native mobile DNS resolution failed"
                );
            }
        }

        // Keep libp2p DNS as fallback exactly so one resolver failure
        // does not remove an official bootstrap source.
        if !native_resolved {
            let fallback = format!("/dns4/{}/tcp/{}", seed, net.default_p2p_port)
                .parse::<libp2p::Multiaddr>()
                .with_context(|| format!("parse fallback mainnet seed {}", seed))?;

            if seen.insert(fallback.to_string()) {
                seeds.push(fallback);
            }
        }
    }

    if seeds.is_empty() {
        anyhow::bail!("mainnet bootstrap produced no usable seed addresses");
    }

    Ok(noid_mobile_node::MobileP2PConfig {
        listen_addr,
        public_addresses: Vec::new(),
        seeds,
        topics,
    })
}

fn start_node_inner(data_dir: String) -> Result<()> {
    android_boot_log(format!("01 start_node_inner ENTER data_dir={}", data_dir));
    let wallet_key = wallet_key_path(&data_dir);
    let wallet_marker = wallet_configured_marker(&data_dir);

    if !wallet_key.is_file() || !wallet_marker.is_file() {
        android_boot_log("02 wallet NOT configured");
        anyhow::bail!("mobile wallet is not configured; create or import a wallet first");
    }

    android_boot_log("02 wallet configured");

    {
        let guard = NODE
            .lock()
            .map_err(|_| anyhow::anyhow!("mobile node state lock poisoned"))?;

        if guard.is_some() {
            anyhow::bail!("mobile node already running");
        }
    }

    android_boot_log("03 entering TOKIO.block_on");

    let (node, p2p) = TOKIO.block_on(async {
        android_boot_log("04 MobileNodeRuntime::open BEGIN");

        let node = match MobileNodeRuntime::open(data_dir).await {
            Ok(node) => {
                android_boot_log("05 MobileNodeRuntime::open OK");
                node
            }

            Err(error) => {
                android_boot_log(format!("05 MobileNodeRuntime::open ERROR: {:#}", error));
                return Err(error).context("open mobile full node");
            }
        };

        let node = Arc::new(node);

        android_boot_log("06 mainnet_p2p_config BEGIN");

        let p2p_config = match mainnet_p2p_config() {
            Ok(config) => {
                android_boot_log(format!(
                    "07 mainnet_p2p_config OK seeds={}",
                    config.seeds.len()
                ));

                for (index, seed) in config.seeds.iter().enumerate() {
                    android_boot_log(format!("07 seed[{}]={}", index, seed));
                }

                config
            }

            Err(error) => {
                android_boot_log(format!("07 mainnet_p2p_config ERROR: {:#}", error));
                return Err(error).context("build mobile mainnet P2P config");
            }
        };

        android_boot_log("08 node.start_p2p BEGIN");

        let p2p = match node.start_p2p(p2p_config).await {
            Ok(p2p) => {
                android_boot_log("09 node.start_p2p OK");
                p2p
            }

            Err(error) => {
                android_boot_log(format!("09 node.start_p2p ERROR: {:#}", error));
                return Err(error).context("start mobile mainnet P2P");
            }
        };

        Ok::<_, anyhow::Error>((node, p2p))
    })?;

    android_boot_log("10 TOKIO.block_on complete");

    let mut guard = NODE
        .lock()
        .map_err(|_| anyhow::anyhow!("mobile node state lock poisoned"))?;

    if guard.is_some() {
        p2p.abort();
        anyhow::bail!("mobile node started concurrently");
    }

    *guard = Some(RunningNode {
        node,
        p2p: Some(p2p),
    });

    android_boot_log("11 NODE global installed");

    Ok(())
}

// ==========================================================================
// WALLET SETUP / BACKUP
// ==========================================================================

fn wallet_key_path(data_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(data_dir).join("wallet.key")
}

fn wallet_configured_marker(data_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(data_dir).join("mobile-wallet.configured")
}

fn wallet_artifact_paths(data_dir: &str) -> [std::path::PathBuf; 4] {
    let key = wallet_key_path(data_dir);

    [
        key.clone(),
        key.with_extension("meta"),
        key.with_extension("history"),
        key.with_extension("receipts"),
    ]
}

fn ensure_node_stopped() -> Result<()> {
    let guard = NODE
        .lock()
        .map_err(|_| anyhow::anyhow!("mobile node state lock poisoned"))?;

    if guard.is_some() {
        anyhow::bail!("stop the mobile node before changing the wallet");
    }

    Ok(())
}

fn wallet_configured_inner(data_dir: String) -> WalletPresenceResult {
    let key = wallet_key_path(&data_dir);
    let marker = wallet_configured_marker(&data_dir);

    WalletPresenceResult {
        ok: true,
        configured: key.is_file() && marker.is_file(),
        error: None,
    }
}

fn remove_wallet_artifacts(data_dir: &str) -> Result<()> {
    for path in wallet_artifact_paths(data_dir) {
        match std::fs::remove_file(&path) {
            Ok(()) => {}

            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}

            Err(error) => {
                return Err(error)
                    .with_context(|| format!("remove wallet artifact {}", path.display()));
            }
        }
    }

    let marker = wallet_configured_marker(data_dir);

    match std::fs::remove_file(&marker) {
        Ok(()) => {}

        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}

        Err(error) => {
            return Err(error)
                .with_context(|| format!("remove wallet configured marker {}", marker.display()));
        }
    }

    Ok(())
}

fn mark_wallet_configured(data_dir: &str) -> Result<()> {
    let marker = wallet_configured_marker(data_dir);

    std::fs::write(&marker, b"PARANO1D-MOBILE-WALLET-V1\n")
        .with_context(|| format!("write wallet configured marker {}", marker.display()))?;

    Ok(())
}

fn create_wallet_inner(data_dir: String) -> Result<()> {
    ensure_node_stopped()?;

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create mobile wallet directory {}", data_dir))?;

    // CREATE NEW WALLET is an explicit destructive choice for any
    // unconfigured wallet artifacts left by older development builds.
    remove_wallet_artifacts(&data_dir)?;

    let key = wallet_key_path(&data_dir);

    let wallet = noid_mobile_node::noid_wallet::WalletState::create_or_load(key.clone())
        .map_err(|error| anyhow::anyhow!("create mobile wallet {}: {error}", key.display()))?;

    drop(wallet);

    mark_wallet_configured(&data_dir)?;

    Ok(())
}

fn import_wallet_inner(data_dir: String, master_key: String) -> Result<()> {
    ensure_node_stopped()?;

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create mobile wallet directory {}", data_dir))?;

    let key = wallet_key_path(&data_dir);

    noid_mobile_node::noid_wallet::state::import_generated_master_secret(&key, &master_key)
        .map_err(|error| anyhow::anyhow!("import mobile wallet: {error}"))?;

    mark_wallet_configured(&data_dir)?;

    Ok(())
}

fn export_wallet_inner(data_dir: String) -> Result<String> {
    let key = wallet_key_path(&data_dir);

    if !key.is_file() {
        anyhow::bail!("wallet is not configured");
    }

    let secret = noid_mobile_node::noid_wallet::state::export_generated_master_secret(&key)
        .map_err(|error| anyhow::anyhow!("export mobile wallet: {error}"))?;

    Ok(secret.to_string())
}

fn delete_wallet_inner(data_dir: String) -> Result<()> {
    stop_node_inner()?;
    remove_wallet_artifacts(&data_dir)?;
    Ok(())
}

// ==========================================================================
// STOP
// ==========================================================================

fn stop_node_inner() -> Result<()> {
    let running = {
        let mut guard = NODE
            .lock()
            .map_err(|_| anyhow::anyhow!("mobile node state lock poisoned"))?;

        guard.take()
    };

    if let Some(running) = running {
        if let Some(p2p) = running.p2p {
            p2p.abort();
        }

        drop(running.node);
    }

    Ok(())
}

// ==========================================================================
// STATUS
// ==========================================================================

fn status_inner() -> NodeStatusResult {
    let (node, health_rx) = {
        let guard = match NODE.lock() {
            Ok(guard) => guard,

            Err(_) => {
                return NodeStatusResult {
                    ok: false,
                    running: false,
                    tip_height: 0,
                    tip_hash: String::new(),
                    peers: 0,
                    syncing: false,
                    sync_state: "ERROR".into(),
                    history_step_ready: false,
                    error: Some("mobile node state lock poisoned".into()),
                };
            }
        };

        let Some(running) = guard.as_ref() else {
            return NodeStatusResult {
                ok: true,
                running: false,
                tip_height: 0,
                tip_hash: String::new(),
                peers: 0,
                syncing: false,
                sync_state: "OFFLINE".into(),
                history_step_ready: false,
                error: None,
            };
        };

        (
            Arc::clone(&running.node),
            running.p2p.as_ref().map(|p2p| p2p.health_receiver()),
        )
    };

    let runtime_status = noid_mobile_node::p2p_runtime::mobile_p2p_status();

    let health = health_rx.as_ref().map(|rx| rx.borrow().clone());

    let (tip_height, tip_hash) =
        TOKIO.block_on(async { (node.tip_height().await, node.tip_hash().await) });

    let connected = health
        .as_ref()
        .map(|h| h.connected_peers)
        .unwrap_or(runtime_status.peers);

    let sync_state = runtime_status.phase.to_string();

    NodeStatusResult {
        ok: true,
        running: true,

        tip_height,

        tip_hash: hex::encode(tip_hash),

        // IMPORTANT:
        // This is now the authoritative transport count from P2PNetwork,
        // not only the MobileP2PRuntime event table.
        peers: connected,

        syncing: runtime_status.syncing,

        sync_state,

        history_step_ready: node.history_step_runtime.is_some(),

        error: None,
    }
}

// ==========================================================================
// WALLET
// ==========================================================================

fn wallet_info_inner() -> WalletInfoResult {
    match with_node(|running| {
        let guard = running
            .node
            .wallet
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet lock poisoned"))?;

        let wallet = guard.as_ref().context("wallet unavailable")?;

        Ok((wallet.active_address(), wallet.balance()))
    }) {
        Ok((address, balance)) => WalletInfoResult {
            ok: true,

            address: Some(hex::encode(address.0)),

            balance_micronoid: balance,

            error: None,
        },

        Err(error) => WalletInfoResult {
            ok: false,

            address: None,

            balance_micronoid: 0,

            error: Some(error.to_string()),
        },
    }
}

// ==========================================================================
// SEND
// ==========================================================================

fn send_inner(destination: String, amount_micronoid: u64, fee_micronoid: u64) -> SendResult {
    let destination = match noid_poseidon2b::primitives::Address::parse(destination.trim()) {
        Ok(address) => address.0,

        Err(error) => {
            return SendResult {
                ok: false,
                txid: None,
                amount_micronoid,
                fee_micronoid,
                input_count: 0,
                output_count: 0,
                error: Some(format!("invalid destination address: {error}")),
            };
        }
    };

    let node = match with_node(|running| Ok(Arc::clone(&running.node))) {
        Ok(node) => node,

        Err(error) => {
            return SendResult {
                ok: false,
                txid: None,
                amount_micronoid,
                fee_micronoid,
                input_count: 0,
                output_count: 0,
                error: Some(error.to_string()),
            };
        }
    };

    match TOKIO.block_on(node.send(destination, amount_micronoid, fee_micronoid)) {
        Ok(result) => SendResult {
            ok: true,

            txid: Some(hex::encode(result.txid)),

            amount_micronoid: result.amount_micronoid,

            fee_micronoid: result.fee_micronoid,

            input_count: result.input_count,

            output_count: result.output_count,

            error: None,
        },

        Err(error) => SendResult {
            ok: false,

            txid: None,

            amount_micronoid,

            fee_micronoid,

            input_count: 0,

            output_count: 0,

            error: Some(error.to_string()),
        },
    }
}

// ==========================================================================
// JNI exports
//
// Kotlin class:
//
// org.parano1d.mobile.NativeNode
// ==========================================================================

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_startNode(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jstring {
    let result = get_string(&mut env, &data_dir).and_then(start_node_inner);

    java_string(
        &mut env,
        json(&BasicResult {
            ok: result.is_ok(),

            error: result.err().map(|error| format!("{error:#}")),
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_walletConfigured(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jstring {
    let result = match get_string(&mut env, &data_dir) {
        Ok(data_dir) => wallet_configured_inner(data_dir),

        Err(error) => WalletPresenceResult {
            ok: false,
            configured: false,
            error: Some(format!("{error:#}")),
        },
    };

    java_string(&mut env, json(&result))
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_createWallet(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jstring {
    let result = get_string(&mut env, &data_dir).and_then(create_wallet_inner);

    java_string(
        &mut env,
        json(&BasicResult {
            ok: result.is_ok(),
            error: result.err().map(|error| format!("{error:#}")),
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_importWallet(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
    master_key: JString,
) -> jstring {
    let result = (|| {
        let data_dir = get_string(&mut env, &data_dir)?;

        let master_key = get_string(&mut env, &master_key)?;

        import_wallet_inner(data_dir, master_key)
    })();

    java_string(
        &mut env,
        json(&BasicResult {
            ok: result.is_ok(),
            error: result.err().map(|error| format!("{error:#}")),
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_exportWallet(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jstring {
    let result = get_string(&mut env, &data_dir).and_then(export_wallet_inner);

    let response = match result {
        Ok(master_key) => ExportWalletResult {
            ok: true,
            master_key: Some(master_key),
            error: None,
        },

        Err(error) => ExportWalletResult {
            ok: false,
            master_key: None,
            error: Some(format!("{error:#}")),
        },
    };

    java_string(&mut env, json(&response))
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_deleteWallet(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
) -> jstring {
    let result = get_string(&mut env, &data_dir).and_then(delete_wallet_inner);

    java_string(
        &mut env,
        json(&BasicResult {
            ok: result.is_ok(),
            error: result.err().map(|error| format!("{error:#}")),
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_stopNode(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = stop_node_inner();

    java_string(
        &mut env,
        json(&BasicResult {
            ok: result.is_ok(),

            error: result.err().map(|error| format!("{error:#}")),
        }),
    )
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_status(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    java_string(&mut env, json(&status_inner()))
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_walletInfo(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    java_string(&mut env, json(&wallet_info_inner()))
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_send(
    mut env: JNIEnv,
    _class: JClass,
    destination: JString,
    amount_micronoid: jlong,
    fee_micronoid: jlong,
) -> jstring {
    if amount_micronoid < 0 || fee_micronoid < 0 {
        return java_string(
            &mut env,
            json(&SendResult {
                ok: false,
                txid: None,
                amount_micronoid: 0,
                fee_micronoid: 0,
                input_count: 0,
                output_count: 0,
                error: Some("negative amount or fee".into()),
            }),
        );
    }

    let destination = match get_string(&mut env, &destination) {
        Ok(value) => value,

        Err(error) => {
            return java_string(
                &mut env,
                json(&SendResult {
                    ok: false,
                    txid: None,
                    amount_micronoid: amount_micronoid as u64,
                    fee_micronoid: fee_micronoid as u64,
                    input_count: 0,
                    output_count: 0,
                    error: Some(error.to_string()),
                }),
            );
        }
    };

    java_string(
        &mut env,
        json(&send_inner(
            destination,
            amount_micronoid as u64,
            fee_micronoid as u64,
        )),
    )
}

fn below_min_fee_required(message: &str) -> Option<u64> {
    let marker = "BelowMinFee: required=";
    let rest = message.split_once(marker)?.1;
    let digits = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();

    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn send_all_inner(destination: String) -> SendResult {
    let destination = match noid_poseidon2b::primitives::Address::parse(destination.trim()) {
        Ok(address) => address.0,
        Err(error) => {
            return SendResult {
                ok: false,
                txid: None,
                amount_micronoid: 0,
                fee_micronoid: 0,
                input_count: 0,
                output_count: 0,
                error: Some(format!("invalid destination address: {error}")),
            };
        }
    };

    let node = match with_node(|running| Ok(Arc::clone(&running.node))) {
        Ok(node) => node,
        Err(error) => {
            return SendResult {
                ok: false,
                txid: None,
                amount_micronoid: 0,
                fee_micronoid: 0,
                input_count: 0,
                output_count: 0,
                error: Some(error.to_string()),
            };
        }
    };

    // SEND ALL is vulnerable to a normal live-chain TOCTOU:
    //
    //   plan at height N -> prove -> block N+1 commits -> mempool admission
    //
    // The new canonical state can raise the deterministic consensus minimum
    // between planning and admission. When admission returns the authoritative
    // BelowMinFee { required, actual }, carry that exact required fee into the
    // next fresh SEND ALL plan and reduce the destination amount by the delta.
    //
    // This preserves the invariant:
    //
    //   amount + fee == currently spendable ACTIVE-address balance
    //
    // and never turns SEND ALL into a cross-address spend.
    let mut minimum_fee_hint = 0u64;

    for attempt in 0..3 {
        let plan = match TOKIO.block_on(node.mobile_plan_send_all()) {
            Ok(plan) => plan,
            Err(error) => {
                return SendResult {
                    ok: false,
                    txid: None,
                    amount_micronoid: 0,
                    fee_micronoid: 0,
                    input_count: 0,
                    output_count: 0,
                    error: Some(format!("{error:#}")),
                };
            }
        };

        let fee_micronoid = plan.fee_micronoid.max(minimum_fee_hint);

        let amount_micronoid = match plan.total_spend_micronoid.checked_sub(fee_micronoid) {
            Some(amount) if amount > 0 => amount,
            _ => {
                return SendResult {
                    ok: false,
                    txid: None,
                    amount_micronoid: 0,
                    fee_micronoid,
                    input_count: plan.input_count,
                    output_count: plan.output_count,
                    error: Some(format!(
                        "InsufficientFunds: active balance {} μNOID does not cover current SEND ALL fee {} μNOID",
                        plan.total_spend_micronoid,
                        fee_micronoid
                    )),
                };
            }
        };

        match TOKIO.block_on(node.send(destination, amount_micronoid, fee_micronoid)) {
            Ok(result) => {
                return SendResult {
                    ok: true,
                    txid: Some(hex::encode(result.txid)),
                    amount_micronoid: result.amount_micronoid,
                    fee_micronoid: result.fee_micronoid,
                    input_count: result.input_count,
                    output_count: result.output_count,
                    error: None,
                };
            }

            Err(error) => {
                let message = format!("{error:#}");

                if let Some(required) = below_min_fee_required(&message) {
                    minimum_fee_hint = minimum_fee_hint.max(required);

                    if attempt < 2 {
                        continue;
                    }
                }

                // Keep the older textual soft-retry compatibility as well.
                let retryable = message.contains("fee below required minimum")
                    || message.contains("InsufficientFunds");

                if attempt < 2 && retryable {
                    continue;
                }

                return SendResult {
                    ok: false,
                    txid: None,
                    amount_micronoid,
                    fee_micronoid,
                    input_count: plan.input_count,
                    output_count: plan.output_count,
                    error: Some(message),
                };
            }
        }
    }

    unreachable!("SEND ALL retry loop always returns")
}

fn recent_transactions_inner(limit: usize) -> RecentTransactionsResult {
    let node = match running_mobile_node() {
        Ok(node) => node,
        Err(error) => {
            return RecentTransactionsResult {
                ok: false,
                transactions: Vec::new(),
                error: Some(error.to_string()),
            };
        }
    };

    match node.mobile_recent_transactions(limit) {
        Ok(items) => RecentTransactionsResult {
            ok: true,
            transactions: items
                .into_iter()
                .map(|item| RecentTransactionJson {
                    txid: hex::encode(item.txid),
                    direction: match item.direction {
                        noid_mobile_node::noid_wallet::state::TxDirection::Sent => "SENT",
                        noid_mobile_node::noid_wallet::state::TxDirection::Received => "RECEIVED",
                    },
                    amount_micronoid: item.amount_micronoid,
                    height: item.height,
                    timestamp: item.timestamp,
                    pending: item.pending,
                    is_coinbase: item.is_coinbase,
                })
                .collect(),
            error: None,
        },
        Err(error) => RecentTransactionsResult {
            ok: false,
            transactions: Vec::new(),
            error: Some(format!("{error:#}")),
        },
    }
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_sendAll(
    mut env: JNIEnv,
    _class: JClass,
    destination: JString,
) -> jstring {
    let destination = match get_string(&mut env, &destination) {
        Ok(value) => value,
        Err(error) => {
            return java_string(
                &mut env,
                json(&SendResult {
                    ok: false,
                    txid: None,
                    amount_micronoid: 0,
                    fee_micronoid: 0,
                    input_count: 0,
                    output_count: 0,
                    error: Some(error.to_string()),
                }),
            );
        }
    };

    java_string(&mut env, json(&send_all_inner(destination)))
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_recentTransactions(
    mut env: JNIEnv,
    _class: JClass,
    limit: jint,
) -> jstring {
    let limit = if limit <= 0 {
        5usize
    } else {
        usize::try_from(limit).unwrap_or(5).min(20)
    };

    java_string(&mut env, json(&recent_transactions_inner(limit)))
}

// ============================================================================
// MOBILE WALLET ADDRESS / BALANCE API
// ============================================================================

#[derive(Serialize)]
struct WalletAddressJson {
    key_index: u32,
    address: String,
    balance_micronoid: u64,
    is_active: bool,
}

#[derive(Serialize)]
struct WalletOverviewJson {
    ok: bool,
    available_balance_micronoid: u64,
    active_balance_micronoid: u64,
    active_index: u32,
    address_count: u32,
    addresses: Vec<WalletAddressJson>,
    error: Option<String>,
}

fn wallet_overview_json(overview: noid_mobile_node::MobileWalletOverview) -> WalletOverviewJson {
    WalletOverviewJson {
        ok: true,
        available_balance_micronoid: overview.available_balance_micronoid,
        active_balance_micronoid: overview.active_balance_micronoid,
        active_index: overview.active_index,
        address_count: overview.address_count,
        addresses: overview
            .addresses
            .into_iter()
            .map(|item| WalletAddressJson {
                key_index: item.key_index,
                address: item.address,
                balance_micronoid: item.balance_micronoid,
                is_active: item.is_active,
            })
            .collect(),
        error: None,
    }
}

fn running_mobile_node() -> Result<Arc<MobileNodeRuntime>> {
    let guard = NODE
        .lock()
        .map_err(|_| anyhow::anyhow!("mobile node state lock poisoned"))?;

    guard
        .as_ref()
        .map(|running| Arc::clone(&running.node))
        .ok_or_else(|| anyhow::anyhow!("mobile node is not running"))
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_walletOverview(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = (|| {
        let node = running_mobile_node()?;

        TOKIO.block_on(node.mobile_wallet_overview())
    })();

    let response = match result {
        Ok(overview) => wallet_overview_json(overview),

        Err(error) => WalletOverviewJson {
            ok: false,
            available_balance_micronoid: 0,
            active_balance_micronoid: 0,
            active_index: 0,
            address_count: 0,
            addresses: Vec::new(),
            error: Some(format!("{error:#}")),
        },
    };

    java_string(&mut env, json(&response))
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_newAddress(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let result = (|| {
        let node = running_mobile_node()?;

        TOKIO.block_on(node.mobile_new_address())?;

        TOKIO.block_on(node.mobile_wallet_overview())
    })();

    let response = match result {
        Ok(overview) => wallet_overview_json(overview),

        Err(error) => WalletOverviewJson {
            ok: false,
            available_balance_micronoid: 0,
            active_balance_micronoid: 0,
            active_index: 0,
            address_count: 0,
            addresses: Vec::new(),
            error: Some(format!("{error:#}")),
        },
    };

    java_string(&mut env, json(&response))
}

#[no_mangle]
pub extern "system" fn Java_org_parano1d_mobile_NativeNode_setActiveAddress(
    mut env: JNIEnv,
    _class: JClass,
    key_index: jni::sys::jint,
) -> jstring {
    let result = (|| {
        let key_index = u32::try_from(key_index)
            .map_err(|_| anyhow::anyhow!("invalid wallet address index"))?;

        let node = running_mobile_node()?;

        TOKIO.block_on(node.mobile_set_active_address(key_index))
    })();

    let response = match result {
        Ok(overview) => wallet_overview_json(overview),

        Err(error) => WalletOverviewJson {
            ok: false,
            available_balance_micronoid: 0,
            active_balance_micronoid: 0,
            active_index: 0,
            address_count: 0,
            addresses: Vec::new(),
            error: Some(format!("{error:#}")),
        },
    };

    java_string(&mut env, json(&response))
}
