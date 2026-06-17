// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

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
use noid_miner::template::{TemplateBuilder, TemplateChainSnapshot};

use crate::api::ParanoidApiServer;
use crate::types::{
    AddressInfo, BlockHeaderInfo, BlockTemplateResponse, ChainInfo, MempoolInfo, MempoolTxInfo,
    MiningInfo, ReceiptVerifyResult, SlotInfo, StateInfo, TxInfo, WalletAddressInfo, WalletBalance,
    WalletHistoryEntry, WalletScanResult, WalletSendResult, WalletStatus, WalletUtxoInfo,
};
use crate::wallet_ops::WalletOps;

fn rpc_err(msg: impl Into<String>) -> ErrorObject<'static> {
    ErrorObject::owned(-32000, msg.into(), None::<()>)
}

#[inline]
fn node_entropy_nonce() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[inline]
fn mix_slot_hint_seed(tip_seed: u64, salt: u64) -> u64 {
    let mut s = tip_seed ^ salt ^ 0x9E37_79B9_7F4A_7C15;
    noid_chain::consensus::allocator::splitmix64(&mut s)
}

fn seed_from_salt_hex(salt_hex: &str) -> Result<u64, ErrorObject<'static>> {
    let salt = salt_hex.trim_start_matches("0x");
    let bytes = hex::decode(salt).map_err(|e| rpc_err(format!("salt hex decode: {e}")))?;
    let mut acc = 0xD6E8_FD9D_AA28_4A7Bu64;
    for chunk in bytes.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        acc ^= u64::from_le_bytes(word);
        acc = noid_chain::consensus::allocator::splitmix64(&mut acc);
    }
    Ok(acc)
}

fn verify_rpc_block_against_context(
    ctx: &mut MdbxChainContext,
    block: &Block,
    block_proof_bytes: &[u8],
    local_time: u64,
) -> Result<(), String> {
    noid_chain::block::validate_block_proof_binding(block, block_proof_bytes)
        .map_err(|e| format!("proof/header binding invalid: {e}"))?;

    let parent = ctx.tip_header().clone();
    let prev_timestamps = ctx.prev_timestamps();
    let prev_active_counts = ctx.prev_active_counts();
    let anchor = ctx.anchor_info();
    noid_chain::consensus::validate_block_checks(
        block,
        &parent,
        &prev_timestamps,
        &prev_active_counts,
        local_time,
        &anchor,
        &ctx.nullifiers,
    )
    .map_err(|e| format!("cheap consensus checks failed: {e}"))?;

    if block_proof_bytes.is_empty() {
        return Ok(());
    }

    let proof: noid_block::BlockProof = bincode::deserialize(block_proof_bytes)
        .map_err(|e| format!("proof deserialize failed: {e}"))?;
    noid_block::validate_block_bucket_tx_indices(block, &proof)
        .map_err(|e| format!("proof bucket coverage invalid: {e:?}"))?;
    if let Some(standard_bucket) = proof.standard_bucket.as_ref() {
        for (tx_index, pi) in standard_bucket.tx_pis.iter().enumerate() {
            if pi.log_slots != block.header.log_slots {
                return Err(format!(
                    "proof log_slots/header binding invalid at standard tx {tx_index}: proof={} header={}",
                    pi.log_slots, block.header.log_slots
                ));
            }
        }
    }
    if let Some(sweep_bucket) = proof.sweep_bucket.as_ref() {
        for (tx_index, pi) in sweep_bucket.tx_pis.iter().enumerate() {
            if pi.log_slots != block.header.log_slots {
                return Err(format!(
                    "proof log_slots/header binding invalid at sweep tx {tx_index}: proof={} header={}",
                    pi.log_slots, block.header.log_slots
                ));
            }
        }
    }

    ctx.preload_segments_for_block(block)
        .map_err(|e| format!("preload segments for ZK validation failed: {e}"))?;

    noid_block::verify_sweep_bucket_from_block(block, &proof)
        .map_err(|e| format!("sweep bucket invalid: {e:?}"))?;
    let sb_airs = noid_block::build_state_binding_airs(block, &proof, &ctx.state.state);
    let sb_refs: Vec<&noid_air::airs::block_state_binding::BlockStateBindingAir> =
        sb_airs.iter().collect();
    if proof.standard_bucket.is_some() {
        let spine = noid_block::build_spine_inputs_list(block);
        let auth = noid_block::build_auth_public_list(block, &proof);
        let tx_airs = noid_block::build_tx_airs(block);
        let air_refs: Vec<&dyn noid_air::Air> =
            tx_airs.iter().map(|a| a as &dyn noid_air::Air).collect();
        noid_block::verify_block(&air_refs, &proof, &spine, &auth, &sb_refs)
            .map_err(|e| format!("ZK proof invalid: {e:?}"))?;
    } else {
        noid_block::verify_state_bindings_standalone(&proof, &sb_refs)
            .map_err(|e| format!("standalone state binding invalid: {e:?}"))?;
    }
    Ok(())
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
    /// Channel to the P2P layer for queries (peer count, etc.).
    pub p2p_cmd: tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    /// One-shot sender: firing this triggers graceful daemon shutdown
    /// (same effect as Ctrl-C). Wrapped in Mutex so the RPC handler can
    /// take ownership on first call.
    pub stop_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    /// Address that receives block rewards in getBlockTemplate.
    /// Always the node operator's address — external callers cannot override this.
    pub mining_payout_address: noid_poseidon2b::primitives::Address,
    /// Optional bearer token for external mining API access.
    /// If None, only localhost callers may use getBlockTemplate / submitBlock
    /// (enforced by binding RPC to 127.0.0.1 by default).
    /// If Some(token), callers must include `Authorization: Bearer <token>`.
    pub mining_key: Option<String>,
    /// When true (requires mining_key to be set), external miners may specify
    /// any valid address as `miner_address` in getBlockTemplate and receive
    /// block rewards directly. The node operator earns via off-chain service fees.
    pub allow_custom_coinbase: bool,
}

impl RpcHandler {
    async fn collect_slot_hints(&self, count: u32, salt_seed: u64) -> RpcResult<Vec<u32>> {
        let count = (count as usize).min(256);
        if count == 0 {
            return Ok(Vec::new());
        }

        let reserved = self.mempool.reserved_output_slots().await;
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let log_slots = tip.log_slots;
        let tip_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap());
        let seed = mix_slot_hint_seed(tip_seed, salt_seed);

        let mut hints = chain
            .state
            .state
            .empty_slot_hints_in_populated_segments(seed, count, &reserved);
        let mut seen: std::collections::HashSet<u32> = reserved;
        seen.extend(hints.iter().copied());

        if hints.len() < count {
            let raw = generate_slot_hints(seed, log_slots, (count * 64).max(512));
            for idx in raw {
                if (idx as u64) < (1u64 << log_slots)
                    && seen.insert(idx)
                    && chain.state.state.slot(idx) == noid_chain::fri_state::SlotValue::EMPTY
                {
                    hints.push(idx);
                    if hints.len() == count {
                        break;
                    }
                }
            }
        }

        hints.truncate(count);
        Ok(hints)
    }
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
        // Compute value independently so the response always reflects the actual FRI state.
        // Never suppress value based on empty — exposes any inconsistency rather than hiding it.
        let value = sv.value.0 as u64;
        let empty = sv == SlotValue::EMPTY;
        let owner_bytes = {
            let mut b = [0u8; 32];
            b[..16].copy_from_slice(&sv.owner_hi.0.to_le_bytes());
            b[16..].copy_from_slice(&sv.owner_lo.0.to_le_bytes());
            b
        };
        use noid_poseidon2b::primitives::Address;
        let owner = if empty {
            String::new()
        } else {
            Address(owner_bytes).to_bech32()
        };
        Ok(SlotInfo {
            slot_index,
            value,
            owner,
            empty,
        })
    }

    async fn get_active_slot_count(&self) -> RpcResult<u64> {
        let chain = self.chain.read().await;
        Ok(chain.state.active_slot_count)
    }

    async fn get_state_info(&self) -> RpcResult<StateInfo> {
        use noid_chain::consensus::params::{EXPAND_DENOM, EXPAND_NUM, LOG_SLOTS_MAX};
        use noid_chain::fri_state::LOG_SEGMENT_SIZE;
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let log_slots = tip.log_slots;
        let active = tip.active_slot_count;

        let capacity = 1u64.checked_shl(log_slots).unwrap_or(u64::MAX);

        // Total number of segments = 2^(log_slots - LOG_SEGMENT_SIZE)
        // At genesis (log_slots=24, LOG_SEGMENT_SIZE=16): 256 segments.
        let num_segments = if log_slots as usize > LOG_SEGMENT_SIZE {
            1usize << (log_slots as usize - LOG_SEGMENT_SIZE)
        } else {
            1
        };

        // Populated = segments with at least one live UTXO. Fully-empty touched
        // segments are dematerialised and excluded from RAM, disk, and snapshots.
        let materialized_in_ram = chain.state.state.materialized_segment_ids().count();
        let nonempty_segments = chain.state.state.active_segment_ids().count();

        // Per-segment on-disk size:
        //   3 columns (values, owners_hi, owners_lo)
        //   × 2^LOG_SEGMENT_SIZE slots
        //   × 16 bytes per Block128
        // = 3 × 65536 × 16 = 3,145,728 bytes = 3 MB
        let seg_size_bytes: u64 = 3 * (1u64 << LOG_SEGMENT_SIZE) * 16;

        // Actual current footprint = only segments that have been written.
        // Virtual-zero segments cost nothing until their first UTXO lands.
        let state_bytes_ram = (materialized_in_ram as u64).saturating_mul(seg_size_bytes);
        let state_bytes_disk = (nonempty_segments as u64).saturating_mul(seg_size_bytes);
        // Theoretical maximum if all slots were filled:
        let state_bytes_max = (num_segments as u64).saturating_mul(seg_size_bytes);

        let fill_pct = if capacity > 0 {
            (active as f64 / capacity as f64 * 10000.0).round() / 100.0
        } else {
            0.0
        };

        let trigger_slots = capacity
            .saturating_mul(EXPAND_NUM)
            .checked_div(EXPAND_DENOM)
            .unwrap_or(0);
        let slots_until_expand = trigger_slots as i64 - active as i64;

        Ok(StateInfo {
            log_slots,
            capacity,
            active_slots: active,
            fill_pct,
            slots_until_expand,
            expand_trigger_pct: (EXPAND_NUM * 100 / EXPAND_DENOM) as u8,
            log_slots_max: LOG_SLOTS_MAX,
            // Real current size (non-zero segments only)
            state_bytes: state_bytes_disk,
            state_size_human: format!(
                "{} RAM  /  {} disk  /  {} max",
                human_bytes(state_bytes_ram),
                human_bytes(state_bytes_disk),
                human_bytes(state_bytes_max),
            ),
        })
    }

    // -----------------------------------------------------------------------
    // New chain methods
    // -----------------------------------------------------------------------

    async fn get_block_hash(&self, height: u64) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        match chain.get_header_from_store(height) {
            Ok(Some(hdr)) => Ok(Some(hex::encode(full_block_hash(&hdr)))),
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_block_header(&self, height: u64) -> RpcResult<Option<BlockHeaderInfo>> {
        use noid_poseidon2b::primitives::Address;
        let chain = self.chain.read().await;
        match chain.get_header_from_store(height) {
            Ok(Some(hdr)) => {
                let hash = full_block_hash(&hdr);
                Ok(Some(BlockHeaderInfo {
                    height: hdr.height,
                    hash: hex::encode(hash),
                    prev_hash: hex::encode(hdr.prev_block_hash),
                    state_root: hex::encode(hdr.state_root),
                    tx_root: hex::encode(hdr.tx_root),
                    timestamp: hdr.timestamp,
                    miner: Address(hdr.miner_address.0).to_bech32(),
                    difficulty_target: hex::encode(hdr.difficulty_target),
                    proof_transcript_hash: hex::encode(hdr.proof_transcript_hash),
                    log_slots: hdr.log_slots,
                    active_slot_count: hdr.active_slot_count,
                    alloc_counter: hdr.alloc_counter,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_slots_by_owner(&self, address: String) -> RpcResult<Vec<SlotInfo>> {
        use noid_poseidon2b::primitives::Address;
        let addr =
            Address::from_str(&address).map_err(|e| rpc_err(format!("invalid address: {e}")))?;
        let chain = self.chain.read().await;
        let utxos = chain
            .store
            .get_utxos_by_owner(&addr.0)
            .map_err(|e| rpc_err(e.to_string()))?;
        Ok(utxos
            .into_iter()
            .map(|(slot_index, value)| SlotInfo {
                slot_index,
                value,
                owner: address.clone(),
                empty: false,
            })
            .collect())
    }

    async fn get_tx(&self, txhash: String) -> RpcResult<Option<TxInfo>> {
        let hash_bytes: [u8; 32] = hex::decode(&txhash)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| rpc_err("invalid txhash: expected 64-char hex"))?;
        let chain = self.chain.read().await;
        match chain.store.get_tx_index(&hash_bytes) {
            Ok(Some((height, tx_position))) => {
                let block_hash = chain
                    .get_header_from_store(height)
                    .ok()
                    .flatten()
                    .map(|h| hex::encode(full_block_hash(&h)))
                    .unwrap_or_default();
                Ok(Some(TxInfo {
                    tx_hash: txhash,
                    height,
                    block_hash,
                    tx_position,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn is_nullifier(&self, txhash: String) -> RpcResult<bool> {
        use noid_poseidon2b::primitives::TxBodyHash;
        let hash_bytes: [u8; 32] = hex::decode(&txhash)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| rpc_err("invalid txhash: expected 64-char hex"))?;
        let chain = self.chain.read().await;
        Ok(chain.nullifiers.contains(&TxBodyHash(hash_bytes)))
    }

    async fn get_block(&self, height: u64) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        match chain.store.get_recent_block(height) {
            Ok(Some(bytes)) => Ok(Some(hex::encode(bytes))),
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    // -----------------------------------------------------------------------
    // Mining / network info
    // -----------------------------------------------------------------------

    async fn get_mining_info(&self) -> RpcResult<MiningInfo> {
        use noid_chain::consensus::emission::block_reward;
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let height = chain.tip_height();
        let diff = tip.difficulty_target;
        // Count leading zero bits (each leading hex '0' = 4 bits).
        let diff_bits = diff.iter().rev().fold(0u32, |zeros, &b| {
            if zeros % 8 == 0 && b == 0 {
                zeros + 8
            } else if zeros % 8 == 0 {
                zeros + b.leading_zeros()
            } else {
                zeros
            }
        });
        let reward = block_reward(tip.log_slots);
        let rec_height = chain
            .store
            .get_recursive_proof()
            .ok()
            .flatten()
            .and_then(|b| bincode::deserialize::<noid_recursive::RecursiveBlockProof>(&b).ok())
            .map(|p| p.block_height);
        Ok(MiningInfo {
            height,
            difficulty_bits: diff_bits,
            difficulty_target: hex::encode(diff),
            block_reward_micronoid: reward,
            block_reward_noid: reward as f64 / 1_000_000.0,
            active_slot_count: tip.active_slot_count,
            recursive_proof_height: rec_height,
        })
    }

    async fn get_peer_count(&self) -> RpcResult<usize> {
        let count = noid_p2p::P2PNetwork::peer_count_via(&self.p2p_cmd).await;
        Ok(count)
    }

    async fn estimate_fee(&self, n_outputs: u32) -> RpcResult<u64> {
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        Ok(
            noid_chain::consensus::fee_breakdown(1, n_outputs as u64, active_slot_count, log_slots)
                .required_total,
        )
    }

    async fn validate_address(&self, address: String) -> RpcResult<AddressInfo> {
        use noid_poseidon2b::primitives::Address;
        match Address::from_str(&address) {
            Ok(addr) => Ok(AddressInfo {
                valid: true,
                bech32: Some(addr.to_bech32()),
                hex: Some(hex::encode(addr.0)),
                error: None,
            }),
            Err(e) => Ok(AddressInfo {
                valid: false,
                bech32: None,
                hex: None,
                error: Some(e.to_string()),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Wallet support
    // -----------------------------------------------------------------------

    async fn get_slot_hints(&self, count: u32) -> RpcResult<Vec<u32>> {
        self.collect_slot_hints(count, node_entropy_nonce()).await
    }

    async fn get_slot_hints_salted(&self, count: u32, salt_hex: String) -> RpcResult<Vec<u32>> {
        self.collect_slot_hints(count, seed_from_salt_hex(&salt_hex)?)
            .await
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

    async fn get_mempool_size(&self) -> RpcResult<usize> {
        Ok(self.mempool.len().await)
    }

    async fn get_mempool_entry(&self, txhash: String) -> RpcResult<Option<MempoolTxInfo>> {
        let hash_bytes: [u8; 32] = hex::decode(&txhash)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| rpc_err("invalid txhash: expected 64-char hex"))?;
        let hash = noid_poseidon2b::primitives::TxBodyHash(hash_bytes);
        let found = self.mempool.get_entry_by_hash(&hash).await;
        Ok(found.map(|e| MempoolTxInfo {
            tx_hash: txhash,
            fee_micronoid: e.tx.body.fee.min(u64::MAX as u128) as u64,
            fee_rate: e.fee_rate,
            n_inputs: e.tx.body.inputs.iter().filter(|i| i.valid).count(),
            n_outputs: e.tx.body.outputs.iter().filter(|o| o.valid).count(),
            admitted_height: e.admitted_height,
            has_proof: e.cached_algebraic_proof.is_some(),
        }))
    }

    // -----------------------------------------------------------------------
    // Receipt verification
    // -----------------------------------------------------------------------

    async fn verify_receipt(&self, receipt_hex: String) -> RpcResult<ReceiptVerifyResult> {
        use noid_chain::consensus::receipt::{verify_against_header, verify_merkle_inclusion};

        let bytes = hex::decode(&receipt_hex).map_err(|e| rpc_err(format!("hex: {e}")))?;

        let receipt = noid_chain::consensus::receipt::ParanoidReceipt::from_bytes(&bytes)
            .map_err(|e| rpc_err(format!("decode receipt: {e:?}")))?;

        // Verify Merkle inclusion (offline, math only).
        let merkle_valid = verify_merkle_inclusion(&receipt);

        // Verify against canonical chain (look up header by height).
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
        // Security: always use the node operator's payout address for the ZK proof.
        // The coinbase is committed inside the proof — external callers cannot redirect
        // rewards to themselves. The `miner_address` param is accepted for API
        // compatibility but ONLY used when it equals the node's payout address or is empty.
        // This prevents unauthorised coinbase hijacking via the template API.
        let addr = if miner_address.is_empty() {
            // Empty = use node's configured payout address (always allowed).
            self.mining_payout_address
        } else if self.allow_custom_coinbase {
            // --allow-custom-coinbase is active (requires --mining-key):
            // accept any valid address. The bearer token is already validated
            // by the HTTP middleware before we reach this point.
            parse_address_hex(&miner_address)?
        } else {
            // Default: coinbase is locked to the node's payout address.
            // External callers cannot redirect rewards.
            let requested = parse_address_hex(&miner_address)?;
            if requested.0 != self.mining_payout_address.0 {
                return Err(rpc_err(
                    "miner_address must match the node's configured payout address. \
                     Use empty string \"\" to use the node's address, or start the \
                     node with --allow-custom-coinbase (requires --mining-key) to \
                     allow miners to specify their own payout address.",
                ));
            }
            requested
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let builder = TemplateBuilder::new(self.mempool.clone());
        let snapshot = {
            let mut ctx = self.chain.write().await;
            TemplateChainSnapshot::from_context(&mut ctx)
                .map_err(|e| rpc_err(format!("template snapshot: {e:?}")))?
        };
        let prev_state_root = snapshot.prev_state_root();
        let tmpl = builder
            .build_from_snapshot(&snapshot, addr, now)
            .await
            .ok_or_else(|| rpc_err("template build failed"))?;

        let height = tmpl.inner.height;
        let n_txs = tmpl.inner.n_txs();
        let pow_header = tmpl.header_for_pow(0);
        let header_core = noid_chain::consensus::pow::header_core_bytes(&pow_header);
        let diff_target = pow_header.difficulty_target;

        // Run ZK prove so the full block (including proof fields) is ready.
        // External miner only needs to patch the nonce — no other computation required.
        // Coinbase-only blocks prove instantly; user-tx blocks take ~1-3 s.
        let tmpl_for_prove = tmpl.clone();
        let (proof_transcript_hash, witness_root, proof_bytes) =
            tokio::task::spawn_blocking(move || {
                noid_miner::run_prove_block_for_rpc(&tmpl_for_prove, prev_state_root)
            })
            .await
            .map_err(|e| rpc_err(format!("prove task: {e}")))?
            .map_err(|e| rpc_err(format!("prove_block: {e}")))?;

        // Seal block with nonce = 0. External miner patches bytes [144..160].
        let sealed = tmpl.seal(0, proof_transcript_hash, witness_root);
        let block_bytes = sealed.to_bytes();

        // nonce_offset inside block bytes = header starts at byte 0,
        // nonce is at NONCE_OFFSET (144) inside the header.
        let nonce_offset = noid_chain::consensus::pow::NONCE_OFFSET;

        Ok(BlockTemplateResponse {
            header_core_hex: hex::encode(header_core),
            block_hex: hex::encode(block_bytes),
            block_proof_hex: hex::encode(proof_bytes),
            nonce_offset,
            difficulty_target_hex: hex::encode(diff_target),
            height,
            n_txs,
        })
    }

    /// Submit a mined block (from external miner or internal PoW).
    ///
    /// `block_hex`: hex-encoded serialized `Block` bytes.
    /// `block_proof_hex`: serialized `BlockProof` bytes, empty for coinbase-only blocks.
    async fn submit_block(&self, block_hex: String, block_proof_hex: String) -> RpcResult<String> {
        let bytes = hex::decode(&block_hex).map_err(|e| rpc_err(format!("block hex: {e}")))?;
        let block =
            Block::from_bytes(&bytes).map_err(|e| rpc_err(format!("decode block: {e:?}")))?;
        let block_proof_bytes = if block_proof_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(&block_proof_hex).map_err(|e| rpc_err(format!("proof hex: {e}")))?
        };

        let local_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Verify proof-native validity before committing. Native apply repeats
        // consensus/root checks and performs the durable state transition.
        let (hash, new_view) = {
            let mut ctx = self.chain.write().await;
            verify_rpc_block_against_context(&mut ctx, &block, &block_proof_bytes, local_time)
                .map_err(|e| rpc_err(format!("validation: {e}")))?;
            ctx.apply_next_block(&block, local_time)
                .map_err(|e| rpc_err(format!("consensus: {e}")))?;
            if !block_proof_bytes.is_empty() {
                ctx.store
                    .put_block_proof(block.header.height, &block_proof_bytes)
                    .map_err(|e| rpc_err(format!("store block proof: {e}")))?;
            }
            let hash = full_block_hash(&block.header);
            let view = noid_mempool::ChainView::from_mdbx(&ctx);
            (hash, view)
        };

        // Update mempool after confirmed block.
        let confirmed: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| tx.tx_body_hash)
            .collect();
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
        // Auto-fee: until Phase I lands a shape-aware estimate API, use a
        // conservative per-tx upper bound that is valid for either Standard4x8
        // or Sweep25x2. Auto-split treats this as a per-transaction fee.
        let effective_fee = if fee_micronoid == 0 {
            let floor = self.mempool.fee_floor().await;
            let (active_slot_count, log_slots) = self.mempool.fee_context().await;
            let standard_fee =
                noid_chain::consensus::fee_breakdown(1, 2, active_slot_count, log_slots)
                    .required_total;
            let sweep_fee =
                noid_chain::consensus::fee_breakdown(25, 2, active_slot_count, log_slots)
                    .required_total;
            standard_fee.max(sweep_fee).max(floor)
        } else {
            fee_micronoid
        };

        // 1. Parse recipient address.
        let to_address = parse_address_hex(&to_hex)?.0;

        // Plan the logical payment before proving. If more than Sweep25x2 can
        // carry, this returns multiple independent chunks.
        let chunks = self
            .wallet
            .plan_send_splits(amount_micronoid, effective_fee)
            .map_err(rpc_err)?;
        if chunks.len() > 1 {
            tracing::info!(
                chunks = chunks.len(),
                amount_micronoid,
                fee_per_tx = effective_fee,
                "wallet_send auto-splitting fragmented payment"
            );
        }

        // Helper: snapshot slot hints. Each chunk/attempt gets a unique seed so
        // split sends do not collide on output slots.
        let call_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;

        let mut tx_hashes = Vec::with_capacity(chunks.len());
        let mut tx_shapes = Vec::with_capacity(chunks.len());

        for (chunk_idx, chunk_amount) in chunks.iter().copied().enumerate() {
            // Retry loop: slots can be claimed between prove_tx and mempool
            // admission. Retry each chunk with fresh hints.
            let mut last_err = String::new();
            let mut submitted = false;

            for attempt in 0..3u32 {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }

                let reserved_outputs = self.mempool.reserved_output_slots().await;

                // Lock 1: extract tip data only (no PRNG or heavy work under lock).
                let (epoch_anchor, log_slots, unique_seed) = {
                    let chain = self.chain.read().await;
                    let tip = chain.tip_header();
                    let log_slots = tip.log_slots;
                    let epoch_anchor = full_block_hash(tip);
                    let tip_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap());
                    let unique_seed = tip_seed.wrapping_add(
                        call_nonce
                            .wrapping_add(attempt as u64)
                            .wrapping_add((chunk_idx as u64).wrapping_mul(0x517cc1b727220a95))
                            .wrapping_mul(0x9e3779b97f4a7c15),
                    );
                    (epoch_anchor, log_slots, unique_seed)
                };
                // PRNG runs without holding the lock.
                let raw = generate_slot_hints(unique_seed, log_slots, 512);
                // Lock 2: filter empty slots only, preferring holes in live segments.
                let slot_hints = {
                    let chain = self.chain.read().await;
                    let mut hints = chain.state.state.empty_slot_hints_in_populated_segments(
                        unique_seed,
                        8,
                        &reserved_outputs,
                    );
                    let mut seen = reserved_outputs.clone();
                    seen.extend(hints.iter().copied());
                    for idx in raw {
                        if (idx as u64) < (1u64 << log_slots)
                            && seen.insert(idx)
                            && chain.state.state.slot(idx)
                                == noid_chain::fri_state::SlotValue::EMPTY
                        {
                            hints.push(idx);
                            if hints.len() == 8 {
                                break;
                            }
                        }
                    }
                    hints
                };

                if slot_hints.len() < 2 {
                    return Err(rpc_err("no empty slot hints available"));
                }

                // Build+prove in spawn_blocking (CPU-heavy).
                let wallet = Arc::clone(&self.wallet);
                let (intent_bytes, input_slots) = match tokio::task::spawn_blocking(move || {
                    wallet.build_send(
                        to_address,
                        chunk_amount,
                        effective_fee,
                        epoch_anchor,
                        slot_hints,
                        log_slots,
                    )
                })
                .await
                {
                    Ok(Ok(parts)) => parts,
                    Ok(Err(e)) => return Err(rpc_err(e)),
                    Err(e) => return Err(rpc_err(format!("task: {e}"))),
                };

                let intent = match noid_tx::TxIntent::from_bytes(&intent_bytes) {
                    Ok(i) => i,
                    Err(e) => return Err(rpc_err(format!("intent decode: {e:?}"))),
                };
                let tx_shape = format!("{:?}", intent.tx_body.shape);
                let failed_tx_hash = intent.tx_body_hash.0;
                let output_slots: Vec<u32> = intent
                    .tx_body
                    .outputs
                    .iter()
                    .filter(|o| o.valid)
                    .map(|o| o.slot_index)
                    .collect();

                match self.mempool.submit(intent, intent_bytes).await {
                    Ok(hash) => {
                        self.wallet.add_pending_inputs(&input_slots);
                        if attempt > 0 {
                            tracing::info!(
                                chunk_idx,
                                attempt,
                                "wallet_send chunk succeeded after retry"
                            );
                        }
                        tx_hashes.push(hex::encode(hash.0));
                        tx_shapes.push(tx_shape);
                        submitted = true;
                        break;
                    }
                    Err(e) => {
                        self.wallet
                            .cleanup_failed_send(failed_tx_hash, &output_slots);
                        last_err = e.to_string();
                        tracing::debug!(chunk_idx, attempt, err = %last_err, "wallet_send chunk conflict, retrying");
                    }
                }
            }

            if !submitted {
                let partial = if tx_hashes.is_empty() {
                    String::new()
                } else {
                    format!("; already submitted chunks: {}", tx_hashes.join(","))
                };
                return Err(rpc_err(format!(
                    "wallet_send chunk {chunk_idx} failed after 3 attempts: {last_err}{partial}"
                )));
            }
        }

        let primary = tx_hashes.first().cloned().unwrap_or_default();
        let primary_shape = tx_shapes.first().cloned();
        let split_count = if tx_hashes.len() > 1 {
            Some(tx_hashes.len())
        } else {
            None
        };
        Ok(WalletSendResult {
            tx_hash: primary,
            fee_micronoid: effective_fee.saturating_mul(tx_hashes.len() as u64),
            tx_hashes,
            split_count,
            shape: primary_shape,
            tx_shapes,
        })
    }

    async fn wallet_export_receipt(&self, txhash_hex: String) -> RpcResult<String> {
        self.wallet.export_receipt(&txhash_hex).map_err(rpc_err)
    }

    async fn wallet_next_address(&self) -> RpcResult<WalletAddressInfo> {
        self.wallet
            .next_address()
            .ok_or_else(|| rpc_err("wallet not initialized"))
    }

    async fn wallet_list_addresses(&self) -> RpcResult<Vec<WalletAddressInfo>> {
        Ok(self.wallet.list_addresses())
    }

    async fn wallet_consolidate(&self, fee_micronoid: u64) -> RpcResult<WalletSendResult> {
        // Consolidation produces exactly 1 output (to self) and may consume up to
        // MAX_INPUTS inputs. Estimate the max-input shape so auto-fee stays valid.
        let effective_fee = if fee_micronoid == 0 {
            let floor = self.mempool.fee_floor().await;
            let (active_slot_count, log_slots) = self.mempool.fee_context().await;
            noid_chain::consensus::fee_breakdown(
                noid_tx::MAX_INPUTS as u64,
                1,
                active_slot_count,
                log_slots,
            )
            .required_total
            .max(floor)
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

            let reserved_outputs = self.mempool.reserved_output_slots().await;

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
                let raw = generate_slot_hints(unique_seed, log_slots, 256);
                let mut hints = chain.state.state.empty_slot_hints_in_populated_segments(
                    unique_seed,
                    4,
                    &reserved_outputs,
                );
                let mut seen = reserved_outputs.clone();
                seen.extend(hints.iter().copied());
                for idx in raw {
                    if (idx as u64) < (1u64 << log_slots)
                        && seen.insert(idx)
                        && chain.state.state.slot(idx) == noid_chain::fri_state::SlotValue::EMPTY
                    {
                        hints.push(idx);
                        if hints.len() == 4 {
                            break;
                        }
                    }
                }
                (epoch_anchor, hints, log_slots)
            };

            if slot_hints.is_empty() {
                return Err(rpc_err("no empty slot hints available"));
            }

            let wallet = Arc::clone(&self.wallet);
            let (intent_bytes, input_slots) = match tokio::task::spawn_blocking(move || {
                wallet.build_consolidate(effective_fee, epoch_anchor, slot_hints, log_slots)
            })
            .await
            {
                Ok(Ok(tuple)) => tuple,
                Ok(Err(e)) => return Err(rpc_err(e)),
                Err(e) => return Err(rpc_err(format!("task: {e}"))),
            };

            let intent = match noid_tx::TxIntent::from_bytes(&intent_bytes) {
                Ok(i) => i,
                Err(e) => return Err(rpc_err(format!("intent decode: {e:?}"))),
            };
            let tx_shape = format!("{:?}", intent.tx_body.shape);

            match self.mempool.submit(intent, intent_bytes).await {
                Ok(hash) => {
                    // Lock input slots only after the tx is accepted by the mempool.
                    // Doing this before submit (as build_consolidate used to do)
                    // caused Bug #3: a failed submit left UTXOs permanently locked,
                    // so every subsequent retry failed to find inputs.
                    self.wallet.add_pending_inputs(&input_slots);
                    let tx_hash = hex::encode(hash.0);
                    return Ok(WalletSendResult {
                        tx_hash: tx_hash.clone(),
                        fee_micronoid: effective_fee,
                        tx_hashes: vec![tx_hash],
                        split_count: None,
                        shape: Some(tx_shape.clone()),
                        tx_shapes: vec![tx_shape],
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
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn human_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Parse an address from bech32m (`noid1…`) or legacy 64-char hex.
/// Empty string → zero address (used when no miner address is configured).
fn parse_address(s: &str) -> RpcResult<noid_poseidon2b::primitives::Address> {
    if s.is_empty() {
        return Ok(noid_poseidon2b::primitives::Address([0u8; 32]));
    }
    noid_poseidon2b::primitives::Address::from_str(s)
        .map_err(|e| rpc_err(format!("invalid address: {e}")))
}

// Keep old name as alias so existing callers compile unchanged.
#[inline]
fn parse_address_hex(s: &str) -> RpcResult<noid_poseidon2b::primitives::Address> {
    parse_address(s)
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
    p2p_cmd: tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    mining_payout_address: noid_poseidon2b::primitives::Address,
    mining_key: Option<String>,
    allow_custom_coinbase: bool,
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
        p2p_cmd,
        stop_tx,
        mining_payout_address,
        mining_key: mining_key.clone(),
        allow_custom_coinbase,
    };

    // Always add the Bearer-auth middleware layer.
    // When mining_key is None it is a transparent pass-through.
    // When Some(key), all requests must carry `Authorization: Bearer <key>`.
    //
    // Pool operators:  paranoid --rpc-listen 0.0.0.0:9401 --mining-key <secret>
    // Solo miners:     no --mining-key; RPC stays on 127.0.0.1 (safe by default)
    let expected_bearer = mining_key.as_deref().map(|k| format!("Bearer {k}"));
    let server = Server::builder()
        .set_http_middleware(tower::ServiceBuilder::new().layer(BearerAuthLayer {
            expected: expected_bearer,
        }))
        .build(listen)
        .await
        .map_err(|e| anyhow::anyhow!("build RPC server: {e}"))?;
    let handle = server.start(handler.into_rpc());
    tracing::debug!(%listen, "RPC server started");
    Ok((handle, stop_rx))
}

// ---------------------------------------------------------------------------
// Simple Bearer-token HTTP middleware
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct BearerAuthLayer {
    /// `None` = pass-through (no auth required). `Some(s)` = require `Authorization: <s>`.
    expected: Option<String>,
}

impl<S> tower::Layer<S> for BearerAuthLayer {
    type Service = BearerAuthService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        BearerAuthService {
            inner,
            expected: self.expected.clone(),
        }
    }
}

#[derive(Clone)]
struct BearerAuthService<S> {
    inner: S,
    expected: Option<String>,
}

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

impl<S, B> tower::Service<http::Request<B>> for BearerAuthService<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<jsonrpsee::server::HttpBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = http::Response<jsonrpsee::server::HttpBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        // No key configured — pass through unconditionally.
        let Some(ref expected) = self.expected else {
            let fut = self.inner.call(req);
            return Box::pin(async move { fut.await });
        };

        let auth = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if auth == expected {
            let fut = self.inner.call(req);
            Box::pin(async move { fut.await })
        } else {
            Box::pin(async {
                Ok(http::Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .header(
                        http::header::WWW_AUTHENTICATE,
                        "Bearer realm=\"paranoid-rpc\"",
                    )
                    .body(jsonrpsee::server::HttpBody::empty())
                    .expect("static 401 response"))
            })
        }
    }
}
