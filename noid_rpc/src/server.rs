// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! JSON-RPC server implementation.
//!
//! All JSON-RPC methods are implemented. See API.md for the full method reference.

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::core::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObject;
use tokio::sync::RwLock;

use noid_chain::block::Block;
use noid_chain::consensus::{allocator::generate_slot_hints, pow::full_block_hash};
use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;
use noid_miner::template::TemplateBuilder;

use crate::api::ParanoidApiServer;
use crate::types::{
    BlockTemplateResponse, ChainInfo, MempoolInfo, MempoolTxInfo, ReceiptVerifyResult, SlotInfo,
    WalletBalance, WalletHistoryEntry, WalletScanResult, WalletSendResult, WalletStatus,
    WalletUtxoInfo,
};
use crate::wallet_ops::WalletOps;

fn rpc_err(msg: impl Into<String>) -> ErrorObject<'static> {
    ErrorObject::owned(-32000, msg.into(), None::<()>)
}

// ---------------------------------------------------------------------------
// RpcHandler
// ---------------------------------------------------------------------------

/// The JSON-RPC handler.
///
/// Holds shared references to the chain context, mempool, and wallet.
/// All state access goes through `Arc<RwLock<MdbxChainContext>>`.
pub struct RpcHandler {
    pub chain: Arc<RwLock<MdbxChainContext>>,
    pub mempool: AsyncMempool,
    pub wallet: Arc<dyn WalletOps + Send + Sync>,
    /// One-shot sender: firing this triggers graceful daemon shutdown
    /// (same effect as Ctrl-C). Wrapped in Mutex so the RPC handler can
    /// take ownership on first call.
    pub stop_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

#[async_trait]
impl ParanoidApiServer for RpcHandler {
    // -----------------------------------------------------------------------
    // Chain state (always available)
    // -----------------------------------------------------------------------

    async fn block_count(&self) -> RpcResult<u64> {
        let chain = self.chain.read().await;
        Ok(chain.tip_height())
    }

    async fn get_chain_info(&self) -> RpcResult<ChainInfo> {
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        Ok(ChainInfo {
            height: chain.tip_height(),
            best_hash: hex::encode(chain.tip_hash()),
            difficulty_target: hex::encode(tip.difficulty_target),
            active_slot_count: tip.active_slot_count,
            log_slots: tip.log_slots,
        })
    }

    async fn get_header_by_height(&self, height: u64) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        match chain.get_header_from_store(height) {
            Ok(Some(hdr)) => {
                let mut buf = Vec::new();
                hdr.encode(&mut buf);
                Ok(Some(hex::encode(buf)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_header_by_hash(&self, hash: String) -> RpcResult<Option<String>> {
        let hash_bytes: [u8; 32] = hex::decode(&hash)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| rpc_err("invalid hash hex (expected 32-byte hex)"))?;
        let chain = self.chain.read().await;
        match chain.store.get_header_by_hash(&hash_bytes) {
            Ok(Some(hdr)) => {
                let mut buf = Vec::new();
                hdr.encode(&mut buf);
                Ok(Some(hex::encode(buf)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_recursive_proof(&self) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        match chain.store.get_recursive_proof() {
            Ok(Some(bytes)) => Ok(Some(hex::encode(bytes))),
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_slot(&self, slot_index: u32) -> RpcResult<SlotInfo> {
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let log_slots = tip.log_slots;
        if (slot_index as u64) >= (1u64 << log_slots) {
            return Err(rpc_err(format!(
                "slot {slot_index} out of range (log_slots={log_slots})"
            )));
        }
        use noid_chain::fri_state::SlotValue;
        let sv = chain.state.state.slot(slot_index);
        let empty = sv == SlotValue::EMPTY;
        // Block128(pub u128): lower 64 bits = value (UTXO balances are u64).
        let value = if empty { 0u64 } else { sv.value.0 as u64 };
        let owner_bytes = {
            let mut b = [0u8; 32];
            b[..16].copy_from_slice(&sv.owner_hi.0.to_le_bytes());
            b[16..].copy_from_slice(&sv.owner_lo.0.to_le_bytes());
            b
        };
        Ok(SlotInfo {
            slot_index,
            value,
            owner: hex::encode(owner_bytes),
            empty,
        })
    }

    async fn get_active_slot_count(&self) -> RpcResult<u64> {
        let chain = self.chain.read().await;
        Ok(chain.state.active_slot_count)
    }

    // -----------------------------------------------------------------------
    // Recent blocks (last 18 only)
    // -----------------------------------------------------------------------

    async fn get_block(&self, height: u64) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        match chain.store.get_recent_block(height) {
            Ok(Some(bytes)) => Ok(Some(hex::encode(bytes))),
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    // -----------------------------------------------------------------------
    // Wallet support
    // -----------------------------------------------------------------------

    async fn get_slot_hints(&self, count: u32) -> RpcResult<Vec<u32>> {
        let count = (count as usize).min(256);
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let log_slots = tip.log_slots;
        let num_slots = 1u32 << log_slots;

        // Wallet slot hints use the tip state_root as seed — completely independent
        // from the miner's alloc_counter PRNG. This minimises collisions between
        // wallet output slots and upcoming coinbase allocations.
        //
        // At genesis difficulty (200ms/block) prove_tx (~300ms) spans 1-2 blocks,
        // so we over-generate 32× to guarantee enough empty candidates survive.
        // At mainnet difficulty (60s/block) this is essentially collision-free.
        let tip_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap());

        let raw = generate_slot_hints(tip_seed, log_slots, (count * 32).max(256));
        let mut hints: Vec<u32> = raw
            .into_iter()
            .filter(|&idx| {
                (idx as u64) < (1u64 << log_slots)
                    && chain.state.state.slot(idx) == noid_chain::fri_state::SlotValue::EMPTY
            })
            .collect();
        hints.dedup();
        hints.truncate(count);
        let _ = num_slots;
        Ok(hints)
    }

    async fn get_epoch_anchor(&self) -> RpcResult<String> {
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let hash = full_block_hash(tip);
        Ok(hex::encode(hash))
    }

    async fn submit_tx_intent(&self, hex_str: String) -> RpcResult<String> {
        let bytes = hex::decode(&hex_str).map_err(|e| rpc_err(format!("hex decode: {e}")))?;
        let intent =
            noid_tx::TxIntent::from_bytes(&bytes).map_err(|e| rpc_err(format!("decode: {e:?}")))?;
        let hash = self
            .mempool
            .submit(intent, bytes)
            .await
            .map_err(|e| rpc_err(e.to_string()))?;
        Ok(hex::encode(hash.0))
    }

    // -----------------------------------------------------------------------
    // Receipt verification
    // -----------------------------------------------------------------------

    async fn verify_receipt(&self, receipt_hex: String) -> RpcResult<ReceiptVerifyResult> {
        use noid_chain::consensus::receipt::{verify_against_header, verify_merkle_inclusion};

        let bytes = hex::decode(&receipt_hex).map_err(|e| rpc_err(format!("hex: {e}")))?;

        let receipt = noid_chain::consensus::receipt::ParanoidReceipt::from_bytes(&bytes)
            .map_err(|e| rpc_err(format!("decode receipt: {e:?}")))?;

        // Step 1: verify Merkle inclusion (offline, math only).
        let merkle_valid = verify_merkle_inclusion(&receipt);

        // Step 2: verify against canonical chain (look up header by height).
        let chain = self.chain.read().await;
        let canonical = match chain.get_header_from_store(receipt.claimed_height) {
            Ok(Some(hdr)) => Some(verify_against_header(&receipt, &hdr)),
            Ok(None) => None,
            Err(_) => None,
        };

        let confirmed = merkle_valid && canonical == Some(true);

        Ok(ReceiptVerifyResult {
            merkle_valid,
            canonical: canonical.unwrap_or(false),
            confirmed,
            error: if !confirmed && canonical.is_none() {
                Some(format!(
                    "header at height {} not found",
                    receipt.claimed_height
                ))
            } else {
                None
            },
        })
    }

    // -----------------------------------------------------------------------
    // Mining — Block Template API
    // -----------------------------------------------------------------------

    /// Get a block template for external miners (or internal use).
    ///
    /// Returns the 212-byte `header_core` as hex — the PoW input.
    /// The external miner brute-forces `nonce` such that:
    ///   `Blake3(header_core || nonce) < difficulty_target`
    ///
    /// CANNOT change the coinbase address: it is committed via the
    /// ZK BlockProof which the full node generates. Changing the coinbase
    /// would require regenerating the entire proof.
    async fn get_block_template(&self, miner_address: String) -> RpcResult<BlockTemplateResponse> {
        // Parse miner address (32-byte hex or empty for default).
        let addr = parse_address_hex(&miner_address)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let builder = TemplateBuilder::new(self.mempool.clone());
        let ctx = self.chain.read().await;
        let tmpl = builder
            .build(&ctx, addr, now)
            .await
            .ok_or_else(|| rpc_err("template build failed"))?;

        // Serialize the header_core (212 bytes) as hex for external PoW.
        let header_core = noid_chain::consensus::pow::header_core_bytes(&tmpl.header_for_pow(0));
        let n_txs = tmpl.inner.n_txs();

        Ok(BlockTemplateResponse {
            header_core_hex: hex::encode(header_core),
            height: tmpl.inner.height,
            n_txs,
        })
    }

    /// Submit a mined block (from external miner or internal PoW).
    ///
    /// `block_hex`: hex-encoded serialized `Block` bytes.
    ///
    /// Validates the block via native consensus checks + applies it to the chain.
    async fn submit_block(&self, block_hex: String) -> RpcResult<String> {
        let bytes = hex::decode(&block_hex).map_err(|e| rpc_err(format!("hex: {e}")))?;
        let block =
            Block::from_bytes(&bytes).map_err(|e| rpc_err(format!("decode block: {e:?}")))?;

        let local_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Apply to chain (runs full native consensus validation).
        let hash = {
            let mut ctx = self.chain.write().await;
            ctx.apply_next_block(&block, local_time)
                .map_err(|e| rpc_err(format!("consensus: {e}")))?;
            full_block_hash(&block.header)
        };

        // Update mempool after confirmed block.
        let confirmed: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| tx.tx_body_hash)
            .collect();
        let new_view = {
            let ctx = self.chain.read().await;
            noid_mempool::ChainView::from_mdbx(&ctx)
        };
        self.mempool
            .on_new_block(&confirmed, block.header.height, new_view)
            .await;

        tracing::info!(
            height = block.header.height,
            hash = ?hash,
            "block submitted via RPC"
        );

        Ok(hex::encode(hash))
    }

    // -----------------------------------------------------------------------
    // Wallet RPC methods
    // -----------------------------------------------------------------------

    async fn wallet_status(&self) -> RpcResult<WalletStatus> {
        Ok(self.wallet.status())
    }

    async fn wallet_get_address(&self, index: u32) -> RpcResult<String> {
        self.wallet
            .get_address(index)
            .ok_or_else(|| rpc_err("wallet not initialized"))
    }

    async fn wallet_get_balance(&self) -> RpcResult<WalletBalance> {
        Ok(self.wallet.get_balance())
    }

    async fn wallet_list_utxos(&self) -> RpcResult<Vec<WalletUtxoInfo>> {
        Ok(self.wallet.list_utxos())
    }

    async fn wallet_history(&self) -> RpcResult<Vec<WalletHistoryEntry>> {
        Ok(self.wallet.history())
    }

    async fn wallet_scan(&self) -> RpcResult<WalletScanResult> {
        let chain = self.chain.read().await;
        let height = chain.tip_height();
        Ok(self.wallet.scan_state(&chain.state.state, height))
    }

    async fn wallet_send(
        &self,
        to_hex: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendResult> {
        use noid_chain::consensus::params::{FEE_PER_OUTPUT, MIN_FEE_BASE};

        // Auto-fee: when fee_micronoid == 0, compute the minimum acceptable fee.
        // A send TX typically has 2 outputs (payment + change), so use
        // MIN_FEE_BASE + 2 * FEE_PER_OUTPUT = 9 000 μNOID baseline.
        // Also respect the current dynamic fee floor from the mempool.
        let effective_fee = if fee_micronoid == 0 {
            let floor = self.mempool.fee_floor().await;
            (MIN_FEE_BASE + 2 * FEE_PER_OUTPUT).max(floor)
        } else {
            fee_micronoid
        };

        // 1. Parse recipient address.
        let to_address = parse_address_hex(&to_hex)?.0;

        // Helper: snapshot slot hints.
        // Each call uses a unique seed = tip_state_root XOR current_time_nanos
        // so concurrent wallet_send calls never pick the same output slots.
        let get_hints = |chain: &noid_chain::storage::MdbxChainContext,
                         call_nonce: u64|
         -> (u64, [u8; 32], Vec<u32>, u32) {
            let tip = chain.tip_header();
            let log_slots = tip.log_slots;
            let epoch_anchor = full_block_hash(tip);
            // Unique seed per call: XOR tip_seed with a nonce so concurrent
            // sends on the same tip pick different output slots.
            let tip_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap());
            let unique_seed = tip_seed.wrapping_add(call_nonce.wrapping_mul(0x9e3779b97f4a7c15));
            let raw = generate_slot_hints(unique_seed, log_slots, 256);
            let mut hints: Vec<u32> = raw
                .into_iter()
                .filter(|&idx| {
                    (idx as u64) < (1u64 << log_slots)
                        && chain.state.state.slot(idx) == noid_chain::fri_state::SlotValue::EMPTY
                })
                .collect();
            hints.dedup();
            hints.truncate(8);
            (chain.tip_height(), epoch_anchor, hints, log_slots)
        };
        // Unique nonce for this request: high-resolution timestamp ensures
        // even concurrent requests from the same client diverge.
        let call_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;

        // Retry loop: at genesis difficulty slots can be claimed between prove_tx
        // and mempool admission. Retry up to 3 times with fresh hints.
        let mut last_err = String::new();
        for attempt in 0..3u32 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }

            let (_, epoch_anchor, slot_hints, log_slots) = {
                let chain = self.chain.read().await;
                // Pass nonce + attempt so each retry also gets unique slots
                get_hints(&chain, call_nonce.wrapping_add(attempt as u64))
            };

            if slot_hints.len() < 2 {
                return Err(rpc_err("no empty slot hints available"));
            }

            // Build+prove in spawn_blocking (CPU-heavy: ~0.3–3 s).
            let wallet = Arc::clone(&self.wallet);
            let intent_bytes = match tokio::task::spawn_blocking(move || {
                wallet.build_send(
                    to_address,
                    amount_micronoid,
                    effective_fee,
                    epoch_anchor,
                    slot_hints,
                    log_slots,
                )
            })
            .await
            {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(e)) => return Err(rpc_err(e)),
                Err(e) => return Err(rpc_err(format!("task: {e}"))),
            };

            let intent = match noid_tx::TxIntent::from_bytes(&intent_bytes) {
                Ok(i) => i,
                Err(e) => return Err(rpc_err(format!("intent decode: {e:?}"))),
            };

            match self.mempool.submit(intent, intent_bytes).await {
                Ok(hash) => {
                    if attempt > 0 {
                        tracing::info!(attempt, "wallet_send succeeded after retry");
                    }
                    return Ok(WalletSendResult {
                        tx_hash: hex::encode(hash.0),
                        fee_micronoid: effective_fee,
                    });
                }
                Err(e) => {
                    last_err = e.to_string();
                    tracing::debug!(attempt, err = %last_err, "wallet_send: slot conflict, retrying");
                }
            }
        }

        Err(rpc_err(format!(
            "wallet_send failed after 3 attempts: {last_err}"
        )))
    }

    async fn wallet_export_receipt(&self, txhash_hex: String) -> RpcResult<String> {
        self.wallet.export_receipt(&txhash_hex).map_err(rpc_err)
    }

    async fn wallet_consolidate(&self, fee_micronoid: u64) -> RpcResult<WalletSendResult> {
        use noid_chain::consensus::params::{FEE_PER_OUTPUT, MIN_FEE_BASE};

        // Consolidation always produces exactly 1 output (to self), so the
        // minimum fee is MIN_FEE_BASE + 1 × FEE_PER_OUTPUT = 7 000 μNOID.
        // When fee_micronoid == 0 (auto), also account for the current dynamic
        // fee floor so the TX is never rejected as BelowMinFee.
        let min_consolidate_fee = MIN_FEE_BASE + FEE_PER_OUTPUT;
        let effective_fee = if fee_micronoid == 0 {
            // Auto: use the higher of the protocol minimum and the current floor.
            let floor = self.mempool.fee_floor().await;
            min_consolidate_fee.max(floor)
        } else {
            fee_micronoid
        };

        let call_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;

        let mut last_err = String::new();
        for attempt in 0..3u32 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }

            let (epoch_anchor, slot_hints, log_slots) = {
                let chain = self.chain.read().await;
                let tip = chain.tip_header();
                let log_slots = tip.log_slots;
                let epoch_anchor = full_block_hash(tip);
                let tip_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap());
                let unique_seed = tip_seed.wrapping_add(
                    call_nonce
                        .wrapping_add(attempt as u64)
                        .wrapping_mul(0x9e3779b97f4a7c15),
                );
                let raw = generate_slot_hints(unique_seed, log_slots, 64);
                let mut hints: Vec<u32> = raw
                    .into_iter()
                    .filter(|&idx| {
                        (idx as u64) < (1u64 << log_slots)
                            && chain.state.state.slot(idx)
                                == noid_chain::fri_state::SlotValue::EMPTY
                    })
                    .collect();
                hints.dedup();
                hints.truncate(4);
                (epoch_anchor, hints, log_slots)
            };

            if slot_hints.is_empty() {
                return Err(rpc_err("no empty slot hints available"));
            }

            let wallet = Arc::clone(&self.wallet);
            let intent_bytes = match tokio::task::spawn_blocking(move || {
                wallet.build_consolidate(effective_fee, epoch_anchor, slot_hints, log_slots)
            })
            .await
            {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(e)) => return Err(rpc_err(e)),
                Err(e) => return Err(rpc_err(format!("task: {e}"))),
            };

            let intent = match noid_tx::TxIntent::from_bytes(&intent_bytes) {
                Ok(i) => i,
                Err(e) => return Err(rpc_err(format!("intent decode: {e:?}"))),
            };

            match self.mempool.submit(intent, intent_bytes).await {
                Ok(hash) => {
                    return Ok(WalletSendResult {
                        tx_hash: hex::encode(hash.0),
                        fee_micronoid: effective_fee,
                    });
                }
                Err(e) => {
                    last_err = e.to_string();
                    tracing::debug!(attempt, err = %last_err, "wallet_consolidate: retrying");
                }
            }
        }

        Err(rpc_err(format!(
            "consolidate failed after 3 attempts: {last_err}"
        )))
    }

    // -----------------------------------------------------------------------
    // Node control
    // -----------------------------------------------------------------------

    async fn stop(&self) -> RpcResult<String> {
        // Take the sender (one-shot: subsequent calls are no-ops).
        let taken = self.stop_tx.lock().await.take();
        match taken {
            Some(tx) => {
                tracing::info!("RPC stop command received — initiating graceful shutdown");
                let _ = tx.send(());
                Ok("stopping".to_string())
            }
            None => Ok("already stopping".to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // Mempool inspection
    // -----------------------------------------------------------------------

    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo> {
        let entries = self.mempool.get_all_entries().await;
        let fee_floor = self.mempool.fee_floor().await;

        let txs: Vec<MempoolTxInfo> = entries
            .iter()
            .map(|e| {
                let n_inputs = e.tx.body.inputs.iter().filter(|i| i.valid).count();
                let n_outputs = e.tx.body.outputs.iter().filter(|o| o.valid).count();
                MempoolTxInfo {
                    tx_hash: hex::encode(e.tx.tx_body_hash.0),
                    fee_micronoid: e.tx.body.fee.min(u64::MAX as u128) as u64,
                    fee_rate: e.fee_rate,
                    n_inputs,
                    n_outputs,
                    admitted_height: e.admitted_height,
                    has_proof: e.cached_algebraic_proof.is_some(),
                }
            })
            .collect();

        Ok(MempoolInfo {
            size: txs.len(),
            fee_floor,
            txs,
        })
    }

    async fn get_mempool_size(&self) -> RpcResult<usize> {
        let size = self.mempool.len().await;
        Ok(size)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_address_hex(hex_str: &str) -> RpcResult<noid_poseidon2b::primitives::Address> {
    if hex_str.is_empty() {
        return Ok(noid_poseidon2b::primitives::Address([0u8; 32]));
    }
    let bytes: [u8; 32] = hex::decode(hex_str)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| rpc_err("miner_address must be 32-byte hex or empty"))?;
    Ok(noid_poseidon2b::primitives::Address(bytes))
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Start the JSON-RPC server and return a handle.
///
/// The server runs until `handle.stop()` is called or it is dropped.
/// Start the RPC server and return (handle, stop_rx).
/// `stop_rx` fires when `paranoid_stop` is called via RPC.
pub async fn start_rpc_server(
    listen: SocketAddr,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    wallet: Arc<dyn WalletOps + Send + Sync>,
) -> anyhow::Result<(
    jsonrpsee::server::ServerHandle,
    tokio::sync::oneshot::Receiver<()>,
)> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = Arc::new(tokio::sync::Mutex::new(Some(stop_tx)));

    let handler = RpcHandler {
        chain,
        mempool,
        wallet,
        stop_tx,
    };
    let server = Server::builder().build(listen).await?;
    let handle = server.start(handler.into_rpc());
    tracing::info!(%listen, "RPC server started");
    Ok((handle, stop_rx))
}
