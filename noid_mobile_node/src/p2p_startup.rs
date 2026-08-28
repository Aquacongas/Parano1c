// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Mobile full-node P2P startup and lifecycle owner.
//!
//! This layer owns:
//!
//! - P2PNetwork::start()
//! - release HistoryStep bank identity
//! - configured seed dials
//! - the swarm reactor task
//! - the single authoritative MobileP2PRuntime event actor
//!
//! Consensus/sync decisions remain in noid_networking + MobileSyncCoordinator.

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

use std::sync::Arc;

use anyhow::{Context, Result};
use libp2p::Multiaddr;

use noid_p2p::{protocol::NetworkTopics, BackgroundCapacity, P2PHealthSnapshot, P2PNetwork};

use crate::{p2p_runtime::MobileP2PRuntime, MobileNodeRuntime};

/// Transport/bootstrap configuration for one mobile full node.
///
/// Topic selection is intentionally explicit here. Android/FFI can construct
/// the correct NetworkTopics for mainnet/testnet without embedding desktop
/// CLI/config policy inside the mobile backend.
pub struct MobileP2PConfig {
    /// Local libp2p listen address.
    ///
    /// Example:
    /// `/ip4/0.0.0.0/tcp/9600`
    pub listen_addr: Multiaddr,

    /// Addresses this node advertises to peers.
    pub public_addresses: Vec<Multiaddr>,

    /// Initial bootstrap peers.
    ///
    /// These may be `/dns/...`, `/dnsaddr/...`, `/ip4/...`, etc.
    pub seeds: Vec<Multiaddr>,

    /// Network-specific gossip topics and stream protocol identifiers.
    pub topics: NetworkTopics,
}

impl MobileP2PConfig {
    pub fn new(listen_addr: Multiaddr, topics: NetworkTopics) -> Self {
        Self {
            listen_addr,
            public_addresses: Vec::new(),
            seeds: Vec::new(),
            topics,
        }
    }

    pub fn with_seed(mut self, seed: Multiaddr) -> Self {
        self.seeds.push(seed);
        self
    }

    pub fn with_seeds(mut self, seeds: impl IntoIterator<Item = Multiaddr>) -> Self {
        self.seeds.extend(seeds);
        self
    }

    pub fn with_public_address(mut self, address: Multiaddr) -> Self {
        self.public_addresses.push(address);
        self
    }
}

/// Running mobile full-node networking.
///
/// There are exactly two authoritative background tasks:
///
/// 1. `reactor_task` — libp2p swarm/transport reactor owned by noid_p2p.
/// 2. `event_task` — one MobileP2PRuntime consumer for required/gossip events.
///
/// P2PNetwork permits only one authoritative required-event subscription,
/// therefore no additional consumer may be attached beside `event_task`.
pub struct MobileP2PHandle {
    network: Arc<P2PNetwork>,

    reactor_task: tokio::task::JoinHandle<anyhow::Result<()>>,

    event_task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl MobileP2PHandle {
    pub fn network(&self) -> &Arc<P2PNetwork> {
        &self.network
    }

    pub fn command_sender(&self) -> noid_p2p::NetworkCommandSender {
        self.network.cmd_tx.clone()
    }

    pub fn health_receiver(&self) -> tokio::sync::watch::Receiver<P2PHealthSnapshot> {
        self.network.health_receiver()
    }

    pub async fn peer_count(&self) -> usize {
        self.network.peer_count().await
    }

    pub fn reactor_finished(&self) -> bool {
        self.reactor_task.is_finished()
    }

    pub fn event_finished(&self) -> bool {
        self.event_task.is_finished()
    }

    /// Wait until either authoritative networking task exits.
    ///
    /// A normally running node should not return from this method.
    pub async fn wait(mut self) -> Result<()> {
        tokio::select! {
            result = &mut self.reactor_task => {
                match result {
                    Ok(Ok(())) => {
                        anyhow::bail!(
                            "mobile P2P reactor stopped unexpectedly"
                        );
                    }

                    Ok(Err(error)) => {
                        Err(error)
                            .context(
                                "mobile P2P reactor failed"
                            )
                    }

                    Err(error) => {
                        Err(anyhow::Error::new(error))
                            .context(
                                "mobile P2P reactor task failed"
                            )
                    }
                }
            }

            result = &mut self.event_task => {
                match result {
                    Ok(Ok(())) => {
                        anyhow::bail!(
                            "mobile P2P event actor stopped unexpectedly"
                        );
                    }

                    Ok(Err(error)) => {
                        Err(error)
                            .context(
                                "mobile P2P event actor failed"
                            )
                    }

                    Err(error) => {
                        Err(anyhow::Error::new(error))
                            .context(
                                "mobile P2P event actor task failed"
                            )
                    }
                }
            }
        }
    }

    /// Abort both background tasks.
    ///
    /// This is primarily the low-level lifecycle primitive for the later
    /// Android/FFI stop operation.
    pub fn abort(&self) {
        self.event_task.abort();
        self.reactor_task.abort();
    }
}

impl MobileNodeRuntime {
    /// Start this mobile full node on the real Parano1d P2P transport.
    ///
    /// Startup order:
    ///
    /// chain + mempool + wallet + HistoryStep runtime
    /// -> P2PNetwork::start
    /// -> seed registration/dial
    /// -> one MobileP2PRuntime actor
    /// -> live header/exact-object synchronization
    pub async fn start_p2p(self: &Arc<Self>, config: MobileP2PConfig) -> Result<MobileP2PHandle> {
        android_boot_log("20 MobileNodeRuntime::start_p2p ENTER");
        let MobileP2PConfig {
            listen_addr,
            public_addresses,
            seeds,
            topics,
        } = config;

        let history_proof_bank_id = crate::history_runtime::history_proof_bank_id();

        tracing::info!(
            listen = %listen_addr,
            bank_id =
                %hex::encode(history_proof_bank_id),
            seeds = seeds.len(),
            "starting mobile full-node P2P"
        );

        // Ordinary mobile wallet/full-node capacity.
        //
        // MiningReserved is deliberately not used because mobile never owns
        // block-production work.
        let background_capacity = BackgroundCapacity::Full;

        android_boot_log(format!(
            "21 P2PNetwork::start BEGIN listen={} seeds={}",
            listen_addr,
            seeds.len()
        ));

        let (network, reactor_task) = P2PNetwork::start(
            listen_addr.clone(),
            public_addresses,
            Arc::clone(&self.chain),
            self.mempool.clone(),
            topics,
            history_proof_bank_id,
            self.data_dir().to_path_buf(),
            background_capacity,
        )
        .map_err(|error| {
            android_boot_log(format!("22 P2PNetwork::start ERROR: {:#}", error));
            error
        })
        .context("start mobile P2P network")?;

        android_boot_log("22 P2PNetwork::start OK");

        tokio::spawn(async {
            for n in 1u32..=10 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                android_boot_log(format!("TOKIO HEARTBEAT {}", n));
            }
        });

        let network = Arc::new(network);

        tracing::info!(
            listen = %listen_addr,
            "mobile P2P reactor started"
        );

        // ------------------------------------------------------------
        // EXACTLY ONE authoritative event consumer.
        // ------------------------------------------------------------

        let runtime = Arc::new(MobileP2PRuntime::new(
            Arc::clone(self),
            Arc::clone(&network),
        ));

        let event_task = tokio::spawn(async move { runtime.run().await });

        // ------------------------------------------------------------
        // Bootstrap only AFTER the authoritative event actor is alive.
        //
        // Otherwise a fast seed connection can publish PeerConnected
        // before MobileP2PRuntime has started consuming node-facing events.
        // Initial bootstrap is triggered from PeerConnected, so losing that
        // event leaves the mobile node permanently at WAITING.
        // ------------------------------------------------------------

        tokio::task::yield_now().await;

        for seed in seeds {
            tracing::info!(
                addr = %seed,
                "dialing mobile bootstrap seed"
            );

            android_boot_log(format!("23 enqueue seed {}", seed));

            network.dial(seed).await;

            android_boot_log("24 seed command queued");
        }

        android_boot_log("25 start_p2p returning handle");

        Ok(MobileP2PHandle {
            network,
            reactor_task,
            event_task,
        })
    }
}
