// SPDX-License-Identifier: Apache-2.0

//! Minimal mobile full-wallet runtime.
//!
//! Reuses:
//! - full WalletState
//! - full MDBX chain state
//! - full ChainView
//! - full AsyncMempool admission
//!
//! Intentionally excludes:
//! - miner
//! - desktop GUI
//! - public RPC server

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};

use noid_chain::storage::MdbxChainContext;
use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
use noid_networking::{header_dag::HeaderDag, sync_plan::SyncPlan};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_wallet::{SharedWallet, WalletState};

use tokio::sync::RwLock;

pub mod p2p_runtime;
pub mod p2p_startup;
pub mod send;
pub mod sync;

pub use noid_wallet;
pub use p2p_startup::{MobileP2PConfig, MobileP2PHandle};

/// Core mobile-node runtime.
///
/// This is deliberately close to the full-node architecture:
///
/// persistent MDBX chain
///       ↓
/// ChainView
///       ↓
/// local AsyncMempool
///
/// plus the same WalletState used by the desktop node.
pub struct MobileNodeRuntime {
    data_dir: PathBuf,

    /// Persistent canonical chain/state.
    pub chain: Arc<RwLock<MdbxChainContext>>,

    /// Full local mempool admission pipeline.
    pub mempool: AsyncMempool,

    /// Shared full-node wallet state.
    pub wallet: SharedWallet,

    /// Shared full-node header DAG used for branch tracking/fork choice.
    pub header_dag: Arc<RwLock<HeaderDag>>,

    /// Current deterministic sync plan.
    pub sync_plan: Arc<RwLock<Option<SyncPlan>>>,

    /// Full mobile synchronization coordinator.
    pub sync: Arc<crate::sync::MobileSyncCoordinator>,

    /// Release-pinned HistoryStep verifier used by exact suffix validation.
    ///
    /// `None` is permitted only for pack-free development builds. Production
    /// release builds embed the canonical HistoryStep pack.
    pub history_step_runtime: Option<Arc<crate::history_runtime::HistoryStepRuntime>>,

    /// Serializes exact suffix commit against mobile wallet/send operations.
    pub apply_gate: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl MobileNodeRuntime {
    /// Open/create mobile chain storage and wallet.
    ///
    /// Layout:
    ///
    /// data_dir/
    ///   chain MDBX files...
    ///   wallet.key
    ///   wallet metadata/history/receipts...
    pub async fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();

        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("create mobile data dir {}", data_dir.display()))?;

        // ------------------------------------------------------------
        // Full persistent chain state
        // ------------------------------------------------------------

        let ctx = MdbxChainContext::open_or_create(&data_dir).context("open mobile MDBX chain")?;

        let chain = Arc::new(RwLock::new(ctx));

        // ------------------------------------------------------------
        // Full local mempool view
        // ------------------------------------------------------------

        let initial_view = {
            let chain_guard = chain.read().await;
            ChainView::from_mdbx(&chain_guard)
        };

        let mempool = AsyncMempool::new(initial_view, MempoolConfig::default());

        // ------------------------------------------------------------
        // Full wallet
        // ------------------------------------------------------------

        let wallet_path = data_dir.join("wallet.key");

        // Mobile wallet creation/import is an explicit user action performed
        // before the full node starts. Never silently create a master secret
        // while opening the node.
        if !wallet_path.is_file() {
            anyhow::bail!(
                "mobile wallet is not configured: {} does not exist",
                wallet_path.display()
            );
        }

        let wallet_state = WalletState::create_or_load(wallet_path)
            .map_err(|error| anyhow::anyhow!("open mobile wallet: {error}"))?;

        let wallet: SharedWallet = Arc::new(Mutex::new(Some(wallet_state)));

        let canonical_dag = {
            let chain_guard = chain.read().await;

            crate::sync::canonical_header_dag(&chain_guard)
                .context("reconstruct mobile canonical HeaderDag")?
        };

        let header_dag = Arc::new(RwLock::new(canonical_dag));
        let sync_plan = Arc::new(RwLock::new(None));

        let committed_tip = {
            let chain_guard = chain.read().await;

            noid_networking::ChainPoint::new(chain_guard.tip_height(), chain_guard.tip_hash())
        };

        let sync = Arc::new(crate::sync::MobileSyncCoordinator::new(
            Arc::clone(&header_dag),
            committed_tip,
        ));

        // ------------------------------------------------------------
        // Release-pinned HistoryStep verifier
        // ------------------------------------------------------------

        let history_step_runtime = crate::history_runtime::embedded_history_step_runtime(&data_dir)
            .map_err(|error| anyhow::anyhow!("initialize mobile HistoryStep runtime: {error}"))?;

        match &history_step_runtime {
            Some(_) => {
                tracing::debug!(
                    bank_id = %hex::encode(
                        crate::history_runtime::history_proof_bank_id()
                    ),
                    "mobile HistoryStep verifier ready"
                );
            }

            None => {
                tracing::warn!(
                    "mobile HistoryStep verifier unavailable in pack-free development build"
                );
            }
        }

        let apply_gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));

        Ok(Self {
            data_dir,
            chain,
            mempool,
            wallet,
            header_dag,
            sync_plan,
            sync,
            history_step_runtime,
            apply_gate,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Current local canonical tip.
    pub async fn tip_height(&self) -> u64 {
        self.chain.read().await.tip_height
    }

    /// Current local canonical tip hash.
    pub async fn tip_hash(&self) -> [u8; 32] {
        self.chain.read().await.tip_hash
    }

    /// Build a fresh mempool ChainView from the durable canonical chain.
    pub async fn current_chain_view(&self) -> ChainView {
        let chain = self.chain.read().await;
        ChainView::from_mdbx(&chain)
    }

    /// Refresh only the canonical ChainView.
    ///
    /// Used after startup/recovery when no block-confirmation event needs
    /// to be emitted.
    pub async fn refresh_mempool_chain_view(&self) {
        let view = self.current_chain_view().await;
        self.mempool.update_chain_view(view).await;
    }

    /// Notify the local mempool after ordinary canonical chain advancement.
    ///
    /// This is the same full-node path used after an exact live suffix:
    ///
    /// - remove confirmed transactions;
    /// - publish TxConfirmed events;
    /// - install the new ChainView;
    /// - evict stale epoch-anchor transactions;
    /// - evict slot conflicts against the new canonical State.
    pub async fn on_canonical_advance(&self, confirmed_tx_hashes: &[TxBodyHash]) {
        let view = self.current_chain_view().await;
        let height = view.tip_height;

        self.mempool
            .on_new_block(confirmed_tx_hashes, height, view)
            .await;
    }

    /// Notify the local mempool after an atomic canonical reorg.
    ///
    /// `reclaimed_tx_hashes` are transactions removed from the old canonical
    /// branch. The full node deliberately does not blindly replay them; it
    /// clears conflicting copies and allows wallets/network peers to resubmit
    /// them against the new canonical state.
    pub async fn on_canonical_reorg(
        &self,
        confirmed_tx_hashes: &[TxBodyHash],
        reclaimed_tx_hashes: Vec<TxBodyHash>,
    ) {
        let view = self.current_chain_view().await;
        let height = view.tip_height;

        self.mempool
            .on_new_block(confirmed_tx_hashes, height, view)
            .await;

        self.mempool.readmit_after_reorg(reclaimed_tx_hashes).await;
    }

    /// Reconcile HeaderDag + ChainCommitter after any successful canonical
    /// advancement or non-final reorganization.
    pub async fn reconcile_sync_after_commit(&self) -> Result<()> {
        let chain = self.chain.read().await;

        self.sync.reconcile_from_chain(&chain).await
    }
}

impl MobileNodeRuntime {
    /// Verify and commit a completely fetched immutable suffix.
    ///
    /// Flow:
    ///
    /// FetchedSuffix
    /// -> body/header binding
    /// -> HistoryStep recursive verification
    /// -> canonical live/reorg commit
    /// -> ChainView update
    /// -> mempool reconciliation
    /// -> HeaderDag/committer reconciliation
    pub async fn apply_fetched_suffix(
        &self,
        fetched: noid_networking::suffix_sync::FetchedSuffix,
    ) -> anyhow::Result<noid_sync_apply::AppliedExactSuffix> {
        let result = noid_sync_apply::apply_exact_suffix(
            &self.chain,
            &self.mempool,
            &self.wallet,
            fetched,
            self.history_step_runtime.clone(),
            self.apply_gate.as_ref(),
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;

        // Canonical MDBX has changed. Update bounded fork-choice authority
        // without throwing away validated competing branches.
        self.reconcile_sync_after_commit().await?;

        Ok(result)
    }
}

pub mod embedded_history_step_pack;
pub mod history_runtime;

// ============================================================================
// Mobile wallet account/address surface
// ============================================================================

/// Number of not-yet-generated addresses inspected after the current local
/// address range. This mirrors the mobile wallet's restore/discovery gap.
pub const MOBILE_WALLET_DISCOVERY_GAP: u32 = 20;

#[derive(Debug, Clone)]
pub struct MobileRecentTransaction {
    pub txid: [u8; 32],
    pub direction: noid_wallet::state::TxDirection,
    pub amount_micronoid: u64,
    pub height: u64,
    pub timestamp: u64,
    pub pending: bool,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone)]
pub struct MobileWalletAddressView {
    pub key_index: u32,
    pub address: String,
    pub balance_micronoid: u64,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct MobileWalletOverview {
    /// Sum of confirmed balances found under every committed wallet address
    /// plus the bounded 20-address discovery look-ahead.
    pub available_balance_micronoid: u64,

    /// Confirmed balance belonging ONLY to the selected active address.
    pub active_balance_micronoid: u64,

    pub active_index: u32,
    pub address_count: u32,
    pub addresses: Vec<MobileWalletAddressView>,
}

impl MobileNodeRuntime {
    /// Build an exact full-wallet view directly from the durable MDBX owner
    /// index.
    ///
    /// Important:
    /// - this does NOT merge UTXOs between accounts;
    /// - AVAILABLE BALANCE is informational only;
    /// - SEND continues to spend only `active_index`;
    /// - a funded address found inside the 20-address look-ahead is committed
    ///   to local wallet metadata so it becomes selectable.
    pub async fn mobile_wallet_overview(&self) -> Result<MobileWalletOverview> {
        let _apply = self.apply_gate.lock().await;

        // Canonical lock order is chain -> wallet.
        let chain = self.chain.read().await;

        let mut wallet_guard = self
            .wallet
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet state lock is poisoned"))?;

        let wallet = wallet_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("wallet is not loaded"))?;

        let original_next = wallet.next_index;
        let active_index = wallet.active_index;

        let scan_end = original_next
            .saturating_add(MOBILE_WALLET_DISCOVERY_GAP)
            .min(noid_wallet::state::MAX_WALLET_ADDRESSES);

        let mut scanned = Vec::with_capacity(scan_end as usize);
        let mut highest_funded_index: Option<u32> = None;
        let mut available_balance_micronoid = 0u64;

        for index in 0..scan_end {
            let address = wallet.address_at(index);
            let snapshot = chain
                .store
                .get_verified_utxos_by_owner(&address.0)
                .map_err(|error| {
                    anyhow::anyhow!("wallet address #{index} verified owner lookup: {error}")
                })?;

            let balance = snapshot
                .utxos
                .iter()
                .try_fold(0u64, |sum, utxo| sum.checked_add(utxo.amount))
                .ok_or_else(|| anyhow::anyhow!("wallet address #{index} balance overflow"))?;

            available_balance_micronoid = available_balance_micronoid
                .checked_add(balance)
                .ok_or_else(|| anyhow::anyhow!("available wallet balance overflow"))?;

            if index >= original_next && balance != 0 {
                highest_funded_index = Some(index);
            }

            scanned.push((index, address, balance));
        }

        // If restore/discovery found used addresses inside the look-ahead,
        // make the whole prefix through the highest used address selectable.
        if let Some(highest) = highest_funded_index {
            let discovered_next = highest
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("wallet discovery index overflow"))?;

            wallet
                .commit_discovered_next_index(active_index, original_next, discovered_next)
                .map_err(|error| {
                    anyhow::anyhow!("commit mobile wallet address discovery: {error}")
                })?;
        }

        let committed_next = wallet.next_index;

        let mut addresses = Vec::with_capacity(committed_next as usize);
        let mut active_balance_micronoid = 0u64;

        for (index, address, balance) in scanned {
            if index >= committed_next {
                continue;
            }

            if index == wallet.active_index {
                active_balance_micronoid = balance;
            }

            addresses.push(MobileWalletAddressView {
                key_index: index,
                address: address.to_bech32(),
                balance_micronoid: balance,
                is_active: index == wallet.active_index,
            });
        }

        Ok(MobileWalletOverview {
            available_balance_micronoid,
            active_balance_micronoid,
            active_index: wallet.active_index,
            address_count: committed_next,
            addresses,
        })
    }

    /// Generate exactly one new inactive address.
    ///
    /// Creating an address NEVER changes the send source.
    pub async fn mobile_new_address(&self) -> Result<MobileWalletAddressView> {
        let _apply = self.apply_gate.lock().await;

        let mut wallet_guard = self
            .wallet
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet state lock is poisoned"))?;

        let wallet = wallet_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("wallet is not loaded"))?;

        let (key_index, address) = wallet
            .create_next_inactive_address()
            .map_err(|error| anyhow::anyhow!("create mobile wallet address: {error}"))?;

        Ok(MobileWalletAddressView {
            key_index,
            address: address.to_bech32(),
            balance_micronoid: 0,
            is_active: false,
        })
    }

    /// Switch the active account using one exact MDBX owner snapshot.
    ///
    /// The wallet cache is replaced only after the snapshot has been verified.
    pub async fn mobile_set_active_address(
        &self,
        target_index: u32,
    ) -> Result<MobileWalletOverview> {
        let _apply = self.apply_gate.lock().await;

        let (reserved_inputs, reserved_outputs) = self.mempool.reserved_slots().await;

        // Canonical lock order: chain -> wallet.
        let chain = self.chain.read().await;

        let mut wallet_guard = self
            .wallet
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet state lock is poisoned"))?;

        let wallet = wallet_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("wallet is not loaded"))?;

        let expected_active_index = wallet.active_index;
        let expected_next_index = wallet.next_index;

        let target_address = wallet
            .preview_generated_index(target_index)
            .map_err(|error| anyhow::anyhow!("{error}"))?;

        let snapshot = chain
            .store
            .get_verified_utxos_by_owner(&target_address.0)
            .map_err(|error| {
                anyhow::anyhow!("verified active-address lookup for #{target_index}: {error}")
            })?;

        wallet
            .commit_verified_activation(
                expected_active_index,
                expected_next_index,
                target_index,
                target_address.0,
                snapshot,
                &reserved_inputs,
                &reserved_outputs,
            )
            .map_err(|error| anyhow::anyhow!("activate wallet address #{target_index}: {error}"))?;

        drop(wallet_guard);
        drop(chain);
        drop(_apply);

        self.mobile_wallet_overview().await
    }

    /// Return newest wallet-history entries first.
    ///
    /// This is wallet-wide display history only; SEND still uses the selected
    /// active address exclusively.
    pub fn mobile_recent_transactions(&self, limit: usize) -> Result<Vec<MobileRecentTransaction>> {
        let guard = self
            .wallet
            .lock()
            .map_err(|_| anyhow::anyhow!("wallet state lock is poisoned"))?;

        let wallet = guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("wallet is not loaded"))?;

        Ok(wallet
            .history
            .iter()
            .rev()
            .take(limit.min(20))
            .map(|entry| MobileRecentTransaction {
                txid: entry.tx_hash,
                direction: entry.direction,
                amount_micronoid: entry.amount_micronoid,
                height: entry.height,
                timestamp: entry.timestamp,
                pending: entry.height == 0,
                is_coinbase: entry.is_coinbase,
            })
            .collect())
    }

    /// Calculate a fresh active-address SEND ALL plan using the current dynamic
    /// mempool fee floor and canonical fee context.
    pub async fn mobile_plan_send_all(&self) -> Result<noid_wallet::submit::WalletSendPlan> {
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let relay_floor = self.mempool.fee_floor().await;

        noid_wallet::submit::plan_send_all(&self.wallet, active_slot_count, log_slots, relay_floor)
            .map_err(anyhow::Error::msg)
    }
}
