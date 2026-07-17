// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! JSON-RPC server implementation.
//!
//! All JSON-RPC methods are implemented. See API.md for the full method reference.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jsonrpsee::core::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObject;
use tokio::sync::RwLock;

use noid_chain::consensus::pow::{
    block_id, pow_header_fields, validate_pow, POW_NONCE_FIELD_INDEX,
};
use noid_chain::consensus::wire_limits::{
    hex_chars_for_bytes, MAX_RPC_RECEIPT_BYTES, MAX_RPC_SALT_BYTES, MAX_TX_INTENT_BYTES_GLOBAL,
};
use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;
use noid_miner::template::{TemplateBuilder, TemplateChainSnapshot};
use noid_miner::{AdaptiveProofCapacity, PreparedBlockAttempt};

use crate::api::ParanoidApiServer;
use crate::types::{
    AddressInfo, BlockHeaderInfo, BlockTemplateResponse, ChainInfo, FeeBreakdownInfo, FeeEstimate,
    MempoolInfo, MempoolTxInfo, MiningInfo, ReceiptInputInfo, ReceiptOutputInfo,
    ReceiptSummaryInfo, ReceiptVerifyResult, SlotInfo, StateInfo, TxInfo, WalletAddressInfo,
    WalletBalance, WalletHistoryEntry, WalletInputLimitExceeded, WalletScanResult, WalletSendPlan,
    WalletSendResult, WalletStatus, WalletUtxoInfo, WALLET_INPUT_LIMIT_EXCEEDED_CODE,
    WALLET_INPUT_LIMIT_EXCEEDED_MESSAGE,
};
use crate::wallet_ops::{WalletActivationPreview, WalletOps, WalletSendPlanError};
use crate::wallet_submit::{
    collect_empty_slot_hints, next_user_epoch_anchor, PendingAdmissionGuard, WalletOperationGate,
};

/// External workers receive only a short-lived capability for immutable
/// node-owned material.  The server retains exactly one attempt across its
/// preparation, PoW, proof and commit lifecycle.
const EXTERNAL_MINING_TEMPLATE_TTL: Duration = Duration::from_secs(30);

type ExternalMiningTemplateId = [u8; 16];

fn rpc_err(msg: impl Into<String>) -> ErrorObject<'static> {
    ErrorObject::owned(-32000, msg.into(), None::<()>)
}

fn wallet_plan_error(error: WalletSendPlanError) -> ErrorObject<'static> {
    match error {
        WalletSendPlanError::InputLimitExceeded { max_inputs } => ErrorObject::owned(
            WALLET_INPUT_LIMIT_EXCEEDED_CODE,
            WALLET_INPUT_LIMIT_EXCEEDED_MESSAGE,
            Some(WalletInputLimitExceeded { max_inputs }),
        ),
        other => rpc_err(other.to_string()),
    }
}

/// Read a canonical slot without treating an MDBX-evicted segment as virtual
/// zero. `SegmentedFriState::slot` intentionally cannot distinguish those at
/// the read call site, so RPC reads hydrate the one needed segment from the
/// durable store. The cache amortizes owner-index responses with many UTXOs in
/// the same segment.
fn read_canonical_slot(
    chain: &MdbxChainContext,
    slot_index: u32,
    segment_cache: &mut HashMap<u16, noid_chain::segmented_state::SegmentColumns>,
) -> Result<noid_chain::fri_state::SlotValue, String> {
    use noid_chain::fri_state::SlotValue;

    let state = &chain.state.state;
    if u64::from(slot_index) >= state.num_slots() {
        return Err(format!("slot {slot_index} is out of range"));
    }
    let segment_log = state.effective_log_segment_size();
    let segment_id = (slot_index >> segment_log) as u16;
    if !state.is_evicted(segment_id) {
        return Ok(state.slot(slot_index));
    }

    if !segment_cache.contains_key(&segment_id) {
        let Some((stored_log, columns)) = chain
            .store
            .get_segment(segment_id)
            .map_err(|error| error.to_string())?
        else {
            return Err(format!(
                "evicted segment {segment_id} is missing from durable state"
            ));
        };
        if usize::from(stored_log) != segment_log {
            return Err(format!(
                "segment {segment_id} depth mismatch: stored {stored_log}, expected {segment_log}"
            ));
        }
        segment_cache.insert(segment_id, columns);
    }

    let local_mask = (1u32 << segment_log) - 1;
    let local_index = (slot_index & local_mask) as usize;
    let columns = &segment_cache[&segment_id];
    if local_index >= columns.values.len()
        || local_index >= columns.owners_hi.len()
        || local_index >= columns.owners_lo.len()
    {
        return Err(format!(
            "segment {segment_id} is too short for local slot {local_index}"
        ));
    }
    Ok(SlotValue {
        value: columns.values[local_index],
        owner_hi: columns.owners_hi[local_index],
        owner_lo: columns.owners_lo[local_index],
    })
}

fn history_step_terminal_bytes(ctx: &MdbxChainContext) -> Result<Option<Vec<u8>>, String> {
    let finalized = ctx.finalized_checkpoint();
    if finalized.height == 0 {
        return Ok(None);
    }
    ctx.store
        .get_history_step_terminal_at(finalized.height, finalized.hash)
        .map_err(|error| {
            format!(
                "HistoryStep terminal read h={} failed: {error}",
                finalized.height
            )
        })
}

#[inline]
fn trim_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

fn encode_pow_fields_hex(header: &noid_chain::BlockHeader) -> String {
    let fields = pow_header_fields(header);
    let mut bytes = Vec::with_capacity(fields.len() * 16);
    for field in fields {
        bytes.extend_from_slice(&field.to_u128().to_le_bytes());
    }
    hex::encode(bytes)
}

fn ensure_hex_max_chars(
    name: &str,
    hex_str: &str,
    max_bytes: usize,
) -> Result<(), ErrorObject<'static>> {
    let hex_str = trim_hex_prefix(hex_str);
    let max_chars = hex_chars_for_bytes(max_bytes);
    if hex_str.len() > max_chars {
        return Err(rpc_err(format!(
            "{name} too large: {} hex chars (max {max_chars}, {max_bytes} bytes)",
            hex_str.len()
        )));
    }
    Ok(())
}

fn decode_bounded_hex(
    name: &str,
    hex_str: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, ErrorObject<'static>> {
    ensure_hex_max_chars(name, hex_str, max_bytes)?;
    hex::decode(trim_hex_prefix(hex_str)).map_err(|e| rpc_err(format!("{name} hex decode: {e}")))
}

fn decode_32_byte_hex(name: &str, hex_str: &str) -> Result<[u8; 32], ErrorObject<'static>> {
    let hex_str = trim_hex_prefix(hex_str);
    if hex_str.len() != 64 {
        return Err(rpc_err(format!("invalid {name}: expected 64-char hex")));
    }
    hex::decode(hex_str)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| rpc_err(format!("invalid {name}: expected 32-byte hex")))
}

fn decode_canonical_fixed_hex<const N: usize>(
    name: &str,
    encoded: &str,
) -> Result<[u8; N], ErrorObject<'static>> {
    if encoded.len() != N.saturating_mul(2) {
        return Err(rpc_err(format!(
            "invalid {name}: expected exactly {} lowercase hex chars",
            N.saturating_mul(2)
        )));
    }
    let decoded = hex::decode(encoded)
        .map_err(|error| rpc_err(format!("invalid {name}: canonical hex decode: {error}")))?;
    if hex::encode(&decoded) != encoded {
        return Err(rpc_err(format!(
            "invalid {name}: expected canonical lowercase hex without a prefix"
        )));
    }
    decoded
        .try_into()
        .map_err(|_| rpc_err(format!("invalid {name}: expected exactly {} bytes", N)))
}

fn decode_external_template_id(
    encoded: &str,
) -> Result<ExternalMiningTemplateId, ErrorObject<'static>> {
    decode_canonical_fixed_hex("template_id", encoded)
}

fn decode_external_nonce_hex(encoded: &str) -> Result<u128, ErrorObject<'static>> {
    let bytes = decode_canonical_fixed_hex::<16>("nonce_hex", encoded)?;
    Ok(u128::from_le_bytes(bytes))
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

fn fee_breakdown_info(
    breakdown: noid_chain::consensus::FeeBreakdown,
    relay_floor: u64,
    paid_total: u64,
) -> FeeBreakdownInfo {
    let relay_total = breakdown.required_total.max(relay_floor);
    let paid_total = paid_total.max(relay_total);
    FeeBreakdownInfo {
        base: breakdown.base,
        input: breakdown.input,
        output: breakdown.output,
        io: breakdown.io,
        state_growth: breakdown.state_growth,
        required_total: breakdown.required_total,
        relay_floor,
        relay_total,
        paid_total,
        burned: breakdown.burned,
        miner_claimable: paid_total.saturating_sub(breakdown.burned),
    }
}

fn mempool_tx_info(entry: noid_mempool::MempoolEntryMetadata) -> MempoolTxInfo {
    use noid_chain::consensus::paged_spend::BlockProofClass;

    let page_count = usize::from(entry.page_count);
    let proof_class = BlockProofClass::for_page_count(page_count)
        .expect("admitted PagedSpend always fits a consensus proof class");
    let requires_b255_miner = matches!(proof_class, BlockProofClass::B255);
    MempoolTxInfo {
        tx_hash: hex::encode(entry.tx_hash.0),
        fee_micronoid: entry.fee_micronoid,
        fee_rate: entry.fee_rate,
        n_inputs: usize::from(entry.n_inputs),
        n_outputs: usize::from(entry.n_outputs),
        page_count,
        minimum_proof_class: if requires_b255_miner { "B255" } else { "B64" }.to_owned(),
        requires_b255_miner,
        admitted_height: entry.admitted_height,
        has_authorization: entry.has_authorization,
    }
}

fn validate_tx_counts(n_inputs: usize, n_outputs: usize) -> Result<(), ErrorObject<'static>> {
    if (1..=noid_tx::MAX_PAGED_SPEND_INPUTS).contains(&n_inputs)
        && (1..=noid_tx::MAX_PAGED_SPEND_OUTPUTS).contains(&n_outputs)
    {
        Ok(())
    } else {
        Err(rpc_err(format!(
            "canonical PagedSpend supports 1..={} inputs and 1..={} outputs, got {n_inputs} and {n_outputs}",
            noid_tx::MAX_PAGED_SPEND_INPUTS,
            noid_tx::MAX_PAGED_SPEND_OUTPUTS,
        )))
    }
}

fn seed_from_salt_hex(salt_hex: &str) -> Result<u64, ErrorObject<'static>> {
    let bytes = decode_bounded_hex("salt", salt_hex, MAX_RPC_SALT_BYTES)?;
    let mut acc = 0xD6E8_FD9D_AA28_4A7Bu64;
    for chunk in bytes.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        acc ^= u64::from_le_bytes(word);
        acc = noid_chain::consensus::allocator::splitmix64(&mut acc);
    }
    Ok(acc)
}

struct CachedExternalMiningTemplate<T> {
    prepared: T,
    template_id: ExternalMiningTemplateId,
    parent_height: u64,
    parent_id: [u8; 32],
    expires_at: Instant,
}

enum ExternalMiningAttemptState<T> {
    Idle,
    Preparing {
        template_id: ExternalMiningTemplateId,
        invalidated: bool,
    },
    Ready(CachedExternalMiningTemplate<T>),
    Proving {
        template_id: ExternalMiningTemplateId,
    },
}

/// The external miner owns one attempt, not a cache of independent proofs.
/// The generic payload keeps the lifecycle testable without constructing a
/// cryptographic witness in unit tests.
struct ExternalMiningAttemptSlot<T> {
    state: ExternalMiningAttemptState<T>,
    namespace: u64,
    next_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalMiningConsumeError {
    Unavailable,
    Stale,
}

impl<T> ExternalMiningAttemptSlot<T> {
    fn new(namespace: u64) -> Self {
        Self {
            state: ExternalMiningAttemptState::Idle,
            namespace,
            next_sequence: 0,
        }
    }

    fn purge_expired(&mut self, now: Instant) {
        let expired = matches!(
            &self.state,
            ExternalMiningAttemptState::Ready(cached) if cached.expires_at <= now
        );
        if expired {
            self.state = ExternalMiningAttemptState::Idle;
        }
    }

    fn reserve_preparation(&mut self, now: Instant) -> Result<ExternalMiningTemplateId, String> {
        self.purge_expired(now);
        if !matches!(self.state, ExternalMiningAttemptState::Idle) {
            return Err("external mining attempt is already active".to_string());
        }
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let mut template_id = [0u8; 16];
        template_id[..8].copy_from_slice(&self.namespace.to_le_bytes());
        template_id[8..].copy_from_slice(&self.next_sequence.to_le_bytes());
        self.state = ExternalMiningAttemptState::Preparing {
            template_id,
            invalidated: false,
        };
        Ok(template_id)
    }

    fn cancel_preparation(&mut self, template_id: ExternalMiningTemplateId) {
        if matches!(
            &self.state,
            ExternalMiningAttemptState::Preparing {
                template_id: active,
                ..
            } if *active == template_id
        ) {
            self.state = ExternalMiningAttemptState::Idle;
        }
    }

    fn install_ready(
        &mut self,
        template_id: ExternalMiningTemplateId,
        prepared: T,
        parent_height: u64,
        parent_id: [u8; 32],
        expires_at: Instant,
    ) -> Result<(), String> {
        let installable = matches!(
            &self.state,
            ExternalMiningAttemptState::Preparing {
                template_id: active,
                invalidated: false,
            } if *active == template_id
        );
        if !installable {
            self.cancel_preparation(template_id);
            return Err("external mining preparation was invalidated".to_string());
        }
        self.state = ExternalMiningAttemptState::Ready(CachedExternalMiningTemplate {
            prepared,
            template_id,
            parent_height,
            parent_id,
            expires_at,
        });
        Ok(())
    }

    fn expire_ready(&mut self, template_id: ExternalMiningTemplateId, now: Instant) {
        if matches!(
            &self.state,
            ExternalMiningAttemptState::Ready(cached)
                if cached.template_id == template_id && cached.expires_at <= now
        ) {
            self.state = ExternalMiningAttemptState::Idle;
        }
    }

    fn begin_proving(
        &mut self,
        template_id: ExternalMiningTemplateId,
        now: Instant,
        tip_height: u64,
        tip_id: [u8; 32],
    ) -> Result<T, ExternalMiningConsumeError> {
        self.purge_expired(now);
        let previous = std::mem::replace(&mut self.state, ExternalMiningAttemptState::Idle);
        match previous {
            ExternalMiningAttemptState::Ready(cached)
                if cached.template_id == template_id
                    && cached.parent_height == tip_height
                    && cached.parent_id == tip_id =>
            {
                self.state = ExternalMiningAttemptState::Proving { template_id };
                Ok(cached.prepared)
            }
            ExternalMiningAttemptState::Ready(cached) if cached.template_id == template_id => {
                Err(ExternalMiningConsumeError::Stale)
            }
            other => {
                self.state = other;
                Err(ExternalMiningConsumeError::Unavailable)
            }
        }
    }

    fn finish_proving(&mut self, template_id: ExternalMiningTemplateId) {
        if matches!(
            &self.state,
            ExternalMiningAttemptState::Proving {
                template_id: active,
                ..
            } if *active == template_id
        ) {
            self.state = ExternalMiningAttemptState::Idle;
        }
    }

    fn invalidate_except(&mut self, tip_height: u64, tip_id: [u8; 32]) {
        match &mut self.state {
            ExternalMiningAttemptState::Idle => {}
            ExternalMiningAttemptState::Preparing { invalidated, .. } => {
                // The parent may have been captured immediately before this
                // canonical advance. Keep the owner occupied until its running
                // preparation returns, but never publish that result.
                *invalidated = true;
            }
            ExternalMiningAttemptState::Ready(cached) => {
                if cached.parent_height != tip_height || cached.parent_id != tip_id {
                    self.state = ExternalMiningAttemptState::Idle;
                }
            }
            // Proving cannot be synchronously cancelled. Keep the slot occupied
            // until its owner exits; atomic commit rejects a replaced parent.
            ExternalMiningAttemptState::Proving { .. } => {}
        }
    }
}

/// A small node-facing handle which immediately drops a ready attempt when a
/// P2P block, reorg or snapshot replaces its parent. Running preparation/proof
/// owners remain occupied until their cancellation-safe lease is dropped.
#[derive(Clone)]
pub struct ExternalMiningAttemptInvalidator {
    inner: Arc<Mutex<ExternalMiningAttemptSlot<PreparedBlockAttempt>>>,
}

impl Default for ExternalMiningAttemptInvalidator {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalMiningAttemptInvalidator {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ExternalMiningAttemptSlot::new(
                node_entropy_nonce(),
            ))),
        }
    }

    pub fn invalidate_for_tip(&self, tip_height: u64, tip_id: [u8; 32]) {
        match self.inner.lock() {
            Ok(mut slot) => slot.invalidate_except(tip_height, tip_id),
            Err(_) => tracing::error!("external mining attempt slot lock poisoned"),
        }
    }

    fn reserve_preparation(&self, now: Instant) -> Result<ExternalMiningPreparationLease, String> {
        let template_id = self
            .inner
            .lock()
            .map_err(|_| "external mining attempt slot lock poisoned".to_string())?
            .reserve_preparation(now)?;
        Ok(ExternalMiningPreparationLease {
            attempts: self.clone(),
            template_id,
            armed: true,
        })
    }

    fn begin_proving(
        &self,
        template_id: ExternalMiningTemplateId,
        now: Instant,
        tip_height: u64,
        tip_id: [u8; 32],
    ) -> Result<ExternalMiningProvingAttempt, ExternalMiningConsumeError> {
        let prepared = self
            .inner
            .lock()
            .map_err(|_| ExternalMiningConsumeError::Unavailable)?
            .begin_proving(template_id, now, tip_height, tip_id)?;
        Ok(ExternalMiningProvingAttempt {
            prepared,
            lease: ExternalMiningProvingLease {
                attempts: self.clone(),
                template_id,
            },
        })
    }
}

struct ExternalMiningPreparationLease {
    attempts: ExternalMiningAttemptInvalidator,
    template_id: ExternalMiningTemplateId,
    armed: bool,
}

impl ExternalMiningPreparationLease {
    const fn template_id(&self) -> ExternalMiningTemplateId {
        self.template_id
    }

    fn install_ready(
        mut self,
        prepared: PreparedBlockAttempt,
        parent_height: u64,
        parent_id: [u8; 32],
        now: Instant,
    ) -> Result<(), String> {
        let expires_at = now
            .checked_add(EXTERNAL_MINING_TEMPLATE_TTL)
            .ok_or_else(|| "external template expiry overflow".to_string())?;
        let retained_bytes = prepared.retained_bytes();
        self.attempts
            .inner
            .lock()
            .map_err(|_| "external mining attempt slot lock poisoned".to_string())?
            .install_ready(
                self.template_id,
                prepared,
                parent_height,
                parent_id,
                expires_at,
            )?;
        self.armed = false;
        tracing::debug!(
            template_id = %hex::encode(self.template_id),
            retained_bytes,
            "external mining attempt staged"
        );

        let attempts = self.attempts.clone();
        let template_id = self.template_id;
        tokio::spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(expires_at)).await;
            match attempts.inner.lock() {
                Ok(mut slot) => slot.expire_ready(template_id, Instant::now()),
                Err(_) => tracing::error!("external mining attempt slot lock poisoned"),
            }
        });
        Ok(())
    }
}

impl Drop for ExternalMiningPreparationLease {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        match self.attempts.inner.lock() {
            Ok(mut slot) => slot.cancel_preparation(self.template_id),
            Err(_) => tracing::error!("external mining attempt slot lock poisoned"),
        }
    }
}

struct ExternalMiningProvingAttempt {
    prepared: PreparedBlockAttempt,
    lease: ExternalMiningProvingLease,
}

struct ExternalMiningProvingLease {
    attempts: ExternalMiningAttemptInvalidator,
    template_id: ExternalMiningTemplateId,
}

impl Drop for ExternalMiningProvingLease {
    fn drop(&mut self) {
        match self.attempts.inner.lock() {
            Ok(mut slot) => slot.finish_proving(self.template_id),
            Err(_) => tracing::error!("external mining attempt slot lock poisoned"),
        }
    }
}

// ---------------------------------------------------------------------------
// RpcHandler
// ---------------------------------------------------------------------------

/// The JSON-RPC handler.
///
/// Holds shared references to the chain context, mempool, and wallet.
/// All state access goes through `Arc<RwLock<MdbxChainContext>>`.
#[derive(Clone)]
pub struct RpcHandler {
    pub chain: Arc<RwLock<MdbxChainContext>>,
    pub mempool: AsyncMempool,
    pub wallet: Arc<dyn WalletOps + Send + Sync>,
    /// Serializes stateful wallet RPC operations from snapshot/reload through
    /// proving and mempool admission. The wallet's short synchronous mutex is
    /// intentionally not held during proving.
    pub wallet_operation_gate: Arc<tokio::sync::Mutex<()>>,
    /// Channel to the P2P layer for queries (peer count, etc.).
    pub p2p_cmd: tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    /// One-shot sender: firing this triggers graceful daemon shutdown
    /// (same effect as Ctrl-C). Wrapped in Mutex so the RPC handler can
    /// take ownership on first call.
    pub stop_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    /// Whether getBlockTemplate/submitBlock are enabled for external PoW workers.
    /// This is true only for nodes explicitly started with `--mode extminer`.
    pub mining_api_enabled: bool,
    /// Explicit configured payout. `None` means resolve the wallet's current
    /// active address for every newly built template.
    pub mining_payout_address: Option<noid_poseidon2b::primitives::Address>,
    /// Optional bearer token for external mining API access.
    /// If None, only localhost callers may use getBlockTemplate / submitBlock
    /// (enforced by binding RPC to 127.0.0.1 by default).
    /// If Some(token), callers must include `Authorization: Bearer <token>`.
    pub mining_key: Option<String>,
    /// When true (requires mining_key to be set), external miners may specify
    /// any valid address as `miner_address` in getBlockTemplate and receive
    /// block rewards directly. The node operator earns via off-chain service fees.
    pub allow_custom_coinbase: bool,
    /// Pinned self-recursive HistoryStep runtime shared with local mining and
    /// inbound bundle verification.
    pub history_step_runtime:
        Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
    /// Process-wide prepared ghost authorization reused by every block attempt.
    pub history_step_ghost: Option<
        Arc<noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization>,
    >,
    /// Every handler clone shares the same one-attempt lifecycle owner.
    external_mining_attempts: ExternalMiningAttemptInvalidator,
    /// Node-side proof capacity for external PoW templates. External workers
    /// do not choose the B64/B255 class.
    external_mining_capacity: Arc<Mutex<AdaptiveProofCapacity>>,
}

impl RpcHandler {
    fn resolved_mining_payout(&self) -> RpcResult<noid_poseidon2b::primitives::Address> {
        if let Some(address) = self.mining_payout_address {
            return Ok(address);
        }
        let (_, address) = self
            .wallet
            .active_address()
            .ok_or_else(|| rpc_err("wallet not initialized"))?;
        parse_address_param(&address)
    }

    async fn install_wallet_activation(
        &self,
        preview: WalletActivationPreview,
    ) -> RpcResult<(WalletAddressInfo, WalletScanResult)> {
        let (reserved_inputs, reserved_outputs) = self.mempool.reserved_slots().await;
        let chain = self.chain.read().await;
        let snapshot = chain
            .store
            .get_verified_utxos_by_owner(&preview.owner)
            .map_err(|error| rpc_err(error.to_string()))?;
        // Keep the chain read guard alive through the wallet commit. A block
        // writer cannot advance the durable tip between lookup and install.
        let result = self
            .wallet
            .commit_activation_snapshot(preview, snapshot, &reserved_inputs, &reserved_outputs)
            .map_err(rpc_err);
        drop(chain);
        result
    }

    async fn reload_active_wallet(&self) -> RpcResult<WalletScanResult> {
        let preview = self.wallet.preview_active_reload().map_err(rpc_err)?;
        let (_address, scan) = self.install_wallet_activation(preview).await?;
        Ok(scan)
    }

    async fn collect_slot_hints(&self, count: u32, salt_seed: u64) -> RpcResult<Vec<u32>> {
        let count = (count as usize).min(256);
        if count == 0 {
            return Ok(Vec::new());
        }

        let reserved = self.mempool.reserved_output_slots().await;
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let tip_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap());
        let seed = mix_slot_hint_seed(tip_seed, salt_seed);

        collect_empty_slot_hints(&chain, &reserved, seed, count).map_err(rpc_err)
    }

    /// Owned preparation coordinator. `getBlockTemplate` runs this in its own
    /// Tokio task, so disconnecting the RPC client cannot drop the one-attempt
    /// lease while a detached blocking/Rayon job still owns the template.
    async fn prepare_external_mining_attempt(
        self,
        requested: Option<noid_poseidon2b::primitives::Address>,
        preparation: ExternalMiningPreparationLease,
    ) -> RpcResult<BlockTemplateResponse> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let builder = TemplateBuilder::new(self.mempool.clone());
        // Snapshot/reorg installation holds the same gate while it replaces
        // chain, mempool and wallet views. Capture the exact parent+payout
        // boundary under that gate, then release it before witness preparation.
        let wallet_operation = self.wallet_operation_gate.lock().await;
        let (snapshot, addr) = {
            let mut ctx = self.chain.write().await;
            let operator_payout = self.resolved_mining_payout()?;
            let addr = match requested {
                None => operator_payout,
                Some(requested) if self.allow_custom_coinbase => requested,
                Some(requested) if requested.0 == operator_payout.0 => requested,
                Some(_) => {
                    return Err(rpc_err(
                        "miner_address must match the node's configured payout address. \
                         Use empty string \"\" to use the node's address, or start the \
                         node with --allow-custom-coinbase (requires --mining-key) to \
                         allow miners to specify their own payout address.",
                    ));
                }
            };
            let snapshot = TemplateChainSnapshot::from_context(&mut ctx)
                .map_err(|e| rpc_err(format!("template snapshot: {e:?}")))?;
            (snapshot, addr)
        };
        drop(wallet_operation);
        let max_user_pages = self
            .external_mining_capacity
            .lock()
            .map_err(|_| rpc_err("external mining capacity lock poisoned"))?
            .page_limit();
        let tmpl = builder
            .build_from_snapshot_with_limit(snapshot, addr, now, max_user_pages)
            .await
            .ok_or_else(|| rpc_err("template build failed"))?;

        let height = tmpl.inner.height;
        let n_txs = tmpl.inner.n_txs();
        let tx_input_counts: Vec<usize> = tmpl
            .inner
            .txs
            .iter()
            .map(|tx| tx.body.live_input_count())
            .collect();
        let tx_output_counts: Vec<usize> = tmpl
            .inner
            .txs
            .iter()
            .map(|tx| tx.body.live_output_count())
            .collect();
        let coinbase_value_micronoid: u64 = tmpl
            .inner
            .coinbase
            .body
            .live_outputs()
            .map(|(_, output)| output.amount)
            .fold(0u64, |acc, value| acc.saturating_add(value));
        let claimable_fees_micronoid = tmpl
            .inner
            .txs
            .iter()
            .map(|tx| {
                noid_chain::consensus::claimable_fee_for_tx_body(
                    &tx.body,
                    tmpl.parent.active_slot_count,
                    tmpl.parent.log_slots,
                )
            })
            .fold(0u64, |acc, fee| acc.saturating_add(fee));
        let pow_header = tmpl.header_for_pow(0);
        let pow_fields_hex = encode_pow_fields_hex(&pow_header);
        let diff_target = pow_header.difficulty_target;

        // Build and prove the complete nonce-independent HistoryStep before
        // exposing the capability. The worker's only remaining job is PoW.
        let runtime = self
            .history_step_runtime
            .as_ref()
            .cloned()
            .ok_or_else(|| rpc_err("HistoryStep runtime is unavailable"))?;
        let ghost = self
            .history_step_ghost
            .as_ref()
            .cloned()
            .ok_or_else(|| rpc_err("HistoryStep producer authorization is unavailable"))?;
        let (prepared, prepare_elapsed) = tokio::task::spawn_blocking(move || {
            let started = Instant::now();
            let result = noid_miner::install_history_step_phase_cpu(|| {
                PreparedBlockAttempt::prepare(tmpl, &runtime, &ghost, now)
            })
            .map_err(|error| format!("HistoryStep CPU admission failed: {error}"))
            .and_then(|result| result);
            (result, started.elapsed())
        })
        .await
        .map_err(|error| rpc_err(format!("HistoryStep preparation task failed: {error}")))?;
        let prepared = prepared
            .map_err(|error| rpc_err(format!("HistoryStep preparation failed: {error}")))?;

        let proof_class = prepared.proof_class();
        let user_pages = prepared.user_page_count();
        let (previous_page_limit, next_page_limit, b64_prepare_ms_ewma, b255_prepare_ms_ewma) = {
            let mut capacity = self
                .external_mining_capacity
                .lock()
                .map_err(|_| rpc_err("external mining capacity lock poisoned"))?;
            let previous = capacity.page_limit();
            capacity.observe_preparation(proof_class, prepare_elapsed);
            (
                previous,
                capacity.page_limit(),
                capacity.prepare_ms_ewma(noid_chain::consensus::paged_spend::BlockProofClass::B64),
                capacity.prepare_ms_ewma(noid_chain::consensus::paged_spend::BlockProofClass::B255),
            )
        };
        tracing::info!(
            mining = "external",
            user_pages,
            ?proof_class,
            max_user_pages,
            previous_page_limit,
            next_page_limit,
            history_step_ms = prepare_elapsed.as_millis(),
            b64_prepare_ms_ewma,
            b255_prepare_ms_ewma,
            "external mining template proved"
        );

        let parent_height = prepared.expected_parent_height();
        let parent_id = prepared.expected_parent_id();
        {
            let chain = self.chain.read().await;
            let tip = chain.tip_header();
            if tip.height != parent_height || block_id(tip) != parent_id {
                return Err(rpc_err(
                    "chain tip changed while preparing external mining template",
                ));
            }
        }

        let template_id = preparation.template_id();
        preparation
            .install_ready(prepared, parent_height, parent_id, Instant::now())
            .map_err(|error| rpc_err(format!("install external mining attempt: {error}")))?;
        Ok(BlockTemplateResponse {
            template_id: hex::encode(template_id),
            pow_fields_hex,
            nonce_field_index: POW_NONCE_FIELD_INDEX,
            difficulty_target_hex: hex::encode(diff_target),
            height,
            expires_in_seconds: EXTERNAL_MINING_TEMPLATE_TTL.as_secs(),
            n_txs,
            tx_input_counts,
            tx_output_counts,
            coinbase_value_micronoid,
            claimable_fees_micronoid,
        })
    }

    /// Seal the sole miner-controlled value into an immutable node-owned
    /// template, check the exact parent and PoW, then finalize it through the
    /// node-owned consensus path.
    async fn finalize_node_owned_template_after_nonce(
        &self,
        prepared: PreparedBlockAttempt,
        nonce: u128,
        nonce_submitted_at: Instant,
    ) -> RpcResult<String> {
        // Consume happened before this check, so a stale or losing template
        // cannot be retried. Atomic apply repeats the parent checks under the
        // chain write lock and closes the race with a peer block.
        {
            let chain = self.chain.read().await;
            let tip = chain.tip_header();
            if tip.height != prepared.expected_parent_height()
                || block_id(tip) != prepared.expected_parent_id()
            {
                return Err(rpc_err("stale external mining template parent"));
            }
        }

        validate_pow(&prepared.pow_header(nonce))
            .map_err(|error| rpc_err(format!("proof of work: {error}")))?;

        let seal_started = Instant::now();
        let runtime = self
            .history_step_runtime
            .as_ref()
            .cloned()
            .ok_or_else(|| rpc_err("HistoryStep runtime is unavailable"))?;
        let proved = tokio::task::spawn_blocking(move || {
            noid_miner::install_history_step_phase_cpu(|| prepared.prove(&runtime, nonce))
                .map_err(|error| format!("HistoryStep CPU admission failed: {error}"))?
        })
        .await
        .map_err(|error| rpc_err(format!("HistoryStep task failed: {error}")))?
        .map_err(|error| rpc_err(format!("HistoryStep prove failed: {error}")))?;
        let seal_ms = seal_started.elapsed().as_millis();
        // Serialize canonical commit + wallet delta + mempool view replacement.
        let wallet_operation = self.wallet_operation_gate.lock().await;
        let chain = Arc::clone(&self.chain);
        let wallet = Arc::clone(&self.wallet);
        let (committed, new_view) = tokio::task::spawn_blocking(move || {
            let mut ctx = chain.blocking_write();
            let committed = proved
                .commit(&mut ctx)
                .map_err(|error| format!("consensus: {error}"))?;
            if let Err(error) = wallet.on_accepted_block(committed.block()) {
                tracing::error!(
                    height = committed.block().header.height,
                    %error,
                    "committed RPC block but wallet update failed"
                );
            }
            let view = noid_mempool::ChainView::from_mdbx(&ctx);
            Ok::<_, String>((committed, view))
        })
        .await
        .map_err(|error| rpc_err(format!("block commit task failed: {error}")))?
        .map_err(rpc_err)?;

        let block = committed.block();
        let height = block.header.height;
        let hash = block_id(&block.header);
        let confirmed = noid_chain::try_compute_logical_txids(&block.transactions)
            .expect("locally committed block has a canonical logical tx stream");
        let n_txs = confirmed.len();
        self.mempool
            .on_new_block(&confirmed, height, new_view)
            .await;
        drop(wallet_operation);

        tracing::info!(
            height,
            hash = %hex::encode(hash),
            txs = n_txs,
            mining = "external",
            seal_ms,
            nonce_to_commit_ms = nonce_submitted_at.elapsed().as_millis(),
            "block accepted"
        );

        let (_block, bundle) = committed.into_parts();
        if let Err(error) = self
            .p2p_cmd
            .send(noid_p2p::NetworkCommand::AnnounceBlock { bundle })
            .await
        {
            tracing::warn!(
                height,
                err = %error,
                "failed to broadcast RPC-submitted block"
            );
        }

        Ok(hex::encode(hash))
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
        let hash_bytes = decode_32_byte_hex("hash", &hash)?;
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

    async fn get_history_step_terminal(&self) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        history_step_terminal_bytes(&chain)
            .map(|bytes| bytes.map(hex::encode))
            .map_err(rpc_err)
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
        let sv = read_canonical_slot(&chain, slot_index, &mut HashMap::new()).map_err(rpc_err)?;
        // Decode both packed limbs independently so the response always reflects
        // the actual FRI state. Never suppress them based on `empty` — that would
        // hide a malformed all-zero-owner/non-zero-value state.
        let value = sv.amount();
        let creation_id = sv.creation_id();
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
            creation_id,
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
        // Per-materialized-segment RAM size:
        //   3 columns (values, owners_hi, owners_lo)
        //   × 2^LOG_SEGMENT_SIZE slots
        //   × 16 bytes per Block128
        // = 3 × 65536 × 16 = 3,145,728 bytes = 3 MB
        let seg_size_bytes: u64 = 3 * (1u64 << LOG_SEGMENT_SIZE) * 16;

        // RAM is still materialized densely while a segment is hot. Durable
        // state and snapshots use canonical sparse records instead.
        let state_bytes_ram = (materialized_in_ram as u64).saturating_mul(seg_size_bytes);
        let state_bytes_disk = chain
            .store
            .encoded_state_bytes()
            .map_err(|error| rpc_err(error.to_string()))?;
        // Theoretical maxima are deliberately reported separately.  The
        // current slot domain grows at the consensus expansion boundary, so
        // its fully-materialised size is not the lifetime protocol ceiling.
        let max_encoded_segment_bytes =
            noid_chain::storage::max_encoded_segment_len_for_eff_log(LOG_SEGMENT_SIZE as u8)
                .unwrap_or(usize::MAX) as u64;
        let state_bytes_current_domain_max =
            (num_segments as u64).saturating_mul(max_encoded_segment_bytes);
        let protocol_num_segments = if LOG_SLOTS_MAX as usize > LOG_SEGMENT_SIZE {
            1u64 << (LOG_SLOTS_MAX as usize - LOG_SEGMENT_SIZE)
        } else {
            1
        };
        let state_bytes_protocol_max =
            protocol_num_segments.saturating_mul(max_encoded_segment_bytes);

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
                "{} materialized RAM  /  {} encoded state  /  {} encoded at 2^{}  /  {} encoded protocol max",
                human_bytes(state_bytes_ram),
                human_bytes(state_bytes_disk),
                human_bytes(state_bytes_current_domain_max),
                log_slots,
                human_bytes(state_bytes_protocol_max),
            ),
        })
    }

    // -----------------------------------------------------------------------
    // New chain methods
    // -----------------------------------------------------------------------

    async fn get_block_hash(&self, height: u64) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        match chain.get_header_from_store(height) {
            Ok(Some(hdr)) => Ok(Some(hex::encode(block_id(&hdr)))),
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_block_header(&self, height: u64) -> RpcResult<Option<BlockHeaderInfo>> {
        use noid_poseidon2b::primitives::Address;
        let chain = self.chain.read().await;
        match chain.get_header_from_store(height) {
            Ok(Some(hdr)) => {
                let hash = block_id(&hdr);
                Ok(Some(BlockHeaderInfo {
                    height: hdr.height,
                    hash: hex::encode(hash),
                    prev_hash: hex::encode(hdr.prev_block_hash),
                    state_root: hex::encode(hdr.state_root),
                    tx_root: hex::encode(hdr.tx_root),
                    timestamp: hdr.timestamp,
                    miner: Address(hdr.miner_address.0).to_bech32(),
                    difficulty_target: hex::encode(hdr.difficulty_target),
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
            Address::parse(&address).map_err(|e| rpc_err(format!("invalid address: {e}")))?;
        let chain = self.chain.read().await;
        let snapshot = chain
            .store
            .get_verified_utxos_by_owner(&addr.0)
            .map_err(|e| rpc_err(e.to_string()))?;
        Ok(snapshot
            .utxos
            .into_iter()
            .map(|utxo| SlotInfo {
                slot_index: utxo.slot_index,
                value: utxo.amount,
                creation_id: utxo.creation_id,
                owner: address.clone(),
                empty: false,
            })
            .collect())
    }

    async fn get_tx(&self, txhash: String) -> RpcResult<Option<TxInfo>> {
        let hash_bytes = decode_32_byte_hex("txhash", &txhash)?;
        let chain = self.chain.read().await;
        match chain.store.get_tx_index(&hash_bytes) {
            Ok(Some((height, tx_position))) => {
                let block_hash = chain
                    .get_header_from_store(height)
                    .ok()
                    .flatten()
                    .map(|h| hex::encode(block_id(&h)))
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
        Ok(MiningInfo {
            height,
            difficulty_bits: diff_bits,
            difficulty_target: hex::encode(diff),
            block_reward_micronoid: reward,
            block_reward_noid: reward as f64 / 1_000_000.0,
            active_slot_count: tip.active_slot_count,
        })
    }

    async fn get_peer_count(&self) -> RpcResult<usize> {
        let count = noid_p2p::P2PNetwork::peer_count_via(&self.p2p_cmd).await;
        Ok(count)
    }

    async fn estimate_fee(&self, n_outputs: u32) -> RpcResult<u64> {
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let floor = self.mempool.fee_floor().await;
        Ok(
            noid_chain::consensus::fee_breakdown(1, n_outputs as u64, active_slot_count, log_slots)
                .required_total
                .max(floor),
        )
    }

    async fn estimate_fee_detailed(&self, n_inputs: u32, n_outputs: u32) -> RpcResult<FeeEstimate> {
        let n_inputs = n_inputs as usize;
        let n_outputs = n_outputs as usize;
        validate_tx_counts(n_inputs, n_outputs)?;
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let floor = self.mempool.fee_floor().await;
        let breakdown = noid_chain::consensus::fee_breakdown(
            n_inputs as u64,
            n_outputs as u64,
            active_slot_count,
            log_slots,
        );
        let relay_total = breakdown.required_total.max(floor);
        let info = fee_breakdown_info(breakdown, floor, relay_total);
        Ok(FeeEstimate {
            n_inputs,
            n_outputs,
            net_new_slots: (n_outputs as u64).saturating_sub(n_inputs as u64),
            active_slot_count,
            log_slots,
            fee_micronoid: info.relay_total,
            breakdown: info,
        })
    }

    async fn validate_address(&self, address: String) -> RpcResult<AddressInfo> {
        use noid_poseidon2b::primitives::Address;
        match Address::parse(&address) {
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
        Ok(hex::encode(
            next_user_epoch_anchor(&chain).map_err(rpc_err)?,
        ))
    }

    async fn submit_tx_intent(&self, hex_str: String) -> RpcResult<String> {
        let bytes = decode_bounded_hex("tx intent", &hex_str, MAX_TX_INTENT_BYTES_GLOBAL)?;
        let intent = noid_tx::PagedSpendIntent::from_bytes(&bytes)
            .map_err(|e| rpc_err(format!("decode: {e:?}")))?;
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
        let hash_bytes = decode_32_byte_hex("txhash", &txhash)?;
        let hash = noid_poseidon2b::primitives::TxBodyHash(hash_bytes);
        let found = self.mempool.get_entry_metadata(&hash).await;
        Ok(found.map(mempool_tx_info))
    }

    // -----------------------------------------------------------------------
    // Receipt verification
    // -----------------------------------------------------------------------

    async fn verify_receipt(&self, receipt_hex: String) -> RpcResult<ReceiptVerifyResult> {
        use noid_chain::consensus::receipt::{verify_against_header, verify_merkle_inclusion};

        let bytes = decode_bounded_hex("receipt", &receipt_hex, MAX_RPC_RECEIPT_BYTES)?;

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
        let authenticated_summary = merkle_valid.then(|| ReceiptSummaryInfo {
            txid: hex::encode(receipt.summary.logical_txid),
            claimed_height: receipt.claimed_height,
            confirmed_unix: receipt.summary.confirmed_unix,
            tx_index: receipt.tx_index,
            tx_count: receipt.tx_count,
            fee_micronoid: receipt.summary.fee_micronoid,
            inputs: receipt
                .summary
                .inputs
                .iter()
                .map(|(slot_index, owner)| ReceiptInputInfo {
                    slot_index: *slot_index,
                    owner: owner.to_bech32(),
                })
                .collect(),
            outputs: receipt
                .summary
                .outputs
                .iter()
                .map(|(slot_index, amount_micronoid, owner)| ReceiptOutputInfo {
                    slot_index: *slot_index,
                    amount_micronoid: *amount_micronoid,
                    owner: owner.to_bech32(),
                })
                .collect(),
        });

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
            authenticated_summary,
        })
    }

    // -----------------------------------------------------------------------
    // Mining — Block Template API
    // -----------------------------------------------------------------------

    /// Get a block template for external miners (or internal use).
    ///
    /// Returns the fixed Poseidon2b PoW field schedule as hex.
    /// The external miner brute-forces `nonce` such that:
    ///   `Poseidon2b(POWHDR__, patched_fields) < difficulty_target`
    ///
    /// Every semantic field, including the coinbase address, is fixed inside
    /// the node-owned prepared attempt. The worker can return only a nonce.
    async fn get_block_template(&self, miner_address: String) -> RpcResult<BlockTemplateResponse> {
        if !self.mining_api_enabled {
            return Err(rpc_err(
                "external mining API is disabled; start this node with --mode extminer",
            ));
        }

        let requested = if miner_address.is_empty() {
            None
        } else {
            Some(parse_address_param(&miner_address)?)
        };
        let preparation = self
            .external_mining_attempts
            .reserve_preparation(Instant::now())
            .map_err(rpc_err)?;
        let handler = self.clone();
        // The task, not the request future, owns the lease. Dropping a client
        // connection detaches this coordinator but cannot admit a second
        // attempt while its blocking preparation is still running.
        tokio::spawn(async move {
            handler
                .prepare_external_mining_attempt(requested, preparation)
                .await
        })
        .await
        .map_err(|error| rpc_err(format!("external mining coordinator failed: {error}")))?
    }

    /// Consume one node-owned template and submit its canonical LE nonce.
    async fn submit_block(&self, template_id: String, nonce_hex: String) -> RpcResult<String> {
        let nonce_submitted_at = Instant::now();
        if !self.mining_api_enabled {
            return Err(rpc_err(
                "external mining API is disabled; start this node with --mode extminer",
            ));
        }

        let template_id = decode_external_template_id(&template_id)?;
        let nonce = decode_external_nonce_hex(&nonce_hex)?;
        let (tip_height, tip_id) = {
            let chain = self.chain.read().await;
            let tip = chain.tip_header();
            (tip.height, block_id(tip))
        };
        let proving = self
            .external_mining_attempts
            .begin_proving(template_id, Instant::now(), tip_height, tip_id)
            .map_err(|error| match error {
                ExternalMiningConsumeError::Unavailable => {
                    rpc_err("external mining template is unknown, expired, consumed, or busy")
                }
                ExternalMiningConsumeError::Stale => {
                    rpc_err("stale external mining template parent")
                }
            })?;
        let handler = self.clone();
        // Keep the Proving marker in an owned task. If the RPC client
        // disconnects, proof/commit continues to own the sole slot and its
        // lease releases it on every return or panic path.
        tokio::spawn(async move {
            let ExternalMiningProvingAttempt { prepared, lease } = proving;
            let _lease = lease;
            handler
                .finalize_node_owned_template_after_nonce(prepared, nonce, nonce_submitted_at)
                .await
        })
        .await
        .map_err(|error| rpc_err(format!("external proving coordinator failed: {error}")))?
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
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        if !self.wallet.status().exists {
            return Err(rpc_err("wallet not initialized"));
        }
        self.reload_active_wallet().await
    }

    async fn wallet_plan_send(
        &self,
        to_address: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendPlan> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.reload_active_wallet().await?;
        let _to_address = parse_address_param(&to_address)?.0;
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let floor = self.mempool.fee_floor().await;
        self.wallet
            .plan_send(
                amount_micronoid,
                if fee_micronoid == 0 {
                    None
                } else {
                    Some(fee_micronoid)
                },
                active_slot_count,
                log_slots,
                floor,
            )
            .map_err(wallet_plan_error)
    }

    async fn wallet_send(
        &self,
        to_address: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendResult> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.reload_active_wallet().await?;
        let to_address = parse_address_param(&to_address)?.0;

        let (fee_active_slot_count, fee_log_slots) = self.mempool.fee_context().await;
        let fee_floor = self.mempool.fee_floor().await;
        let plan = self
            .wallet
            .plan_send(
                amount_micronoid,
                (fee_micronoid != 0).then_some(fee_micronoid),
                fee_active_slot_count,
                fee_log_slots,
                fee_floor,
            )
            .map_err(wallet_plan_error)?;
        tracing::info!(
            amount_micronoid,
            fee_micronoid = plan.fee_micronoid,
            input_count = plan.input_count,
            output_count = plan.output_count,
            "wallet_send deterministic plan ready"
        );

        let call_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        let mut last_error = String::new();
        for attempt in 0..3u32 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
            let reserved_outputs = self.mempool.reserved_output_slots().await;
            let selection = {
                let chain = self.chain.read().await;
                let tip = chain.tip_header();
                let unique_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap())
                    .wrapping_add(
                        call_nonce
                            .wrapping_add(attempt as u64)
                            .wrapping_mul(0x9e37_79b9_7f4a_7c15),
                    );
                next_user_epoch_anchor(&chain).and_then(|epoch_anchor| {
                    collect_empty_slot_hints(
                        &chain,
                        &reserved_outputs,
                        unique_seed,
                        noid_tx::TX_OUTPUTS,
                    )
                    .map(|slot_hints| (epoch_anchor, tip.log_slots, slot_hints))
                })
            };
            let (epoch_anchor, log_slots, slot_hints) = match selection {
                Ok(selection) => selection,
                Err(error) => {
                    last_error = error;
                    break;
                }
            };
            if slot_hints.len() < plan.output_count {
                last_error = "not enough empty output slots available".to_string();
                break;
            }

            let wallet = Arc::clone(&self.wallet);
            let (intent_bytes, input_slots) = match tokio::task::spawn_blocking(move || {
                wallet.build_send(
                    to_address,
                    amount_micronoid,
                    plan.fee_micronoid,
                    epoch_anchor,
                    slot_hints,
                    log_slots,
                )
            })
            .await
            {
                Ok(Ok(parts)) => parts,
                Ok(Err(error)) => {
                    last_error = error;
                    break;
                }
                Err(error) => {
                    last_error = format!("wallet proof task: {error}");
                    break;
                }
            };

            let intent = match noid_tx::PagedSpendIntent::from_bytes(&intent_bytes) {
                Ok(intent) => intent,
                Err(error) => {
                    last_error = format!("intent decode: {error:?}");
                    break;
                }
            };
            let facts = noid_tx::validate_paged_spend(&intent.pages)
                .map_err(|error| rpc_err(format!("wallet PagedSpend: {error}")))?;
            let input_count = usize::from(facts.live_inputs);
            let output_count = usize::from(facts.live_outputs);
            let actual_fee = facts.fee;
            let failed_txid = facts.logical_txid.0;
            let output_slots: Vec<u32> = intent
                .pages
                .iter()
                .flat_map(|page| page.body.live_outputs())
                .map(|(_, output)| output.slot_index)
                .collect();
            if actual_fee != plan.fee_micronoid
                || input_count != plan.input_count
                || output_count != plan.output_count
            {
                last_error = format!(
                    "wallet builder diverged from plan: expected fee/counts {}/{}/{}, got {actual_fee}/{input_count}/{output_count}",
                    plan.fee_micronoid, plan.input_count, plan.output_count
                );
                break;
            }

            let reservation = match PendingAdmissionGuard::reserve(
                Arc::clone(&self.wallet),
                failed_txid,
                input_slots,
                output_slots,
                amount_micronoid,
                to_address,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    last_error = error;
                    break;
                }
            };
            match self.mempool.submit(intent, intent_bytes).await {
                Ok(txid) => {
                    reservation.commit();
                    if attempt > 0 {
                        tracing::info!(attempt, "wallet_send succeeded after retry");
                    }
                    return Ok(WalletSendResult {
                        txid: hex::encode(txid.0),
                        amount_micronoid,
                        fee_micronoid: actual_fee,
                        input_count,
                        output_count,
                    });
                }
                Err(error) => {
                    drop(reservation);
                    last_error = error.to_string();
                }
            }
        }

        Err(rpc_err(format!(
            "wallet send failed after 3 attempts: {last_error}"
        )))
    }

    async fn wallet_export_receipt(&self, txhash_hex: String) -> RpcResult<String> {
        self.wallet.export_receipt(&txhash_hex).map_err(rpc_err)
    }

    async fn wallet_next_address(&self) -> RpcResult<WalletAddressInfo> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.reload_active_wallet().await?;
        let preview = self.wallet.preview_next_address().map_err(rpc_err)?;
        let (generated, _scan) = self.install_wallet_activation(preview).await?;
        Ok(generated)
    }

    async fn wallet_list_addresses(&self) -> RpcResult<Vec<WalletAddressInfo>> {
        Ok(self.wallet.list_addresses())
    }

    async fn wallet_active_address(&self) -> RpcResult<WalletAddressInfo> {
        let (key_index, address) = self
            .wallet
            .active_address()
            .ok_or_else(|| rpc_err("wallet not initialized"))?;
        Ok(WalletAddressInfo {
            address,
            key_index,
            is_active: true,
        })
    }

    async fn wallet_set_active_address(&self, index: u32) -> RpcResult<WalletAddressInfo> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.reload_active_wallet().await?;
        let preview = self.wallet.preview_address_switch(index).map_err(rpc_err)?;
        let (activated, _scan) = self.install_wallet_activation(preview).await?;
        Ok(activated)
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
        let snapshot = self.mempool.metadata_snapshot().await;

        let txs: Vec<MempoolTxInfo> = snapshot
            .entries
            .iter()
            .copied()
            .map(mempool_tx_info)
            .collect();

        Ok(MempoolInfo {
            size: txs.len(),
            fee_floor: snapshot.fee_floor,
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

/// Parse an address from canonical bech32m (`o1…`).
/// Empty string → zero address (used when no miner address is configured).
fn parse_address(s: &str) -> RpcResult<noid_poseidon2b::primitives::Address> {
    if s.is_empty() {
        return Ok(noid_poseidon2b::primitives::Address([0u8; 32]));
    }
    noid_poseidon2b::primitives::Address::parse(s)
        .map_err(|e| rpc_err(format!("invalid address: {e}")))
}

#[inline]
fn parse_address_param(s: &str) -> RpcResult<noid_poseidon2b::primitives::Address> {
    parse_address(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_mining_slot_owns_exactly_one_attempt() {
        let now = Instant::now();
        let mut slot = ExternalMiningAttemptSlot::new(7);
        let template_id = slot.reserve_preparation(now).unwrap();
        assert!(slot.reserve_preparation(now).is_err());
        slot.install_ready(
            template_id,
            "prepared",
            11,
            [3u8; 32],
            now + Duration::from_secs(30),
        )
        .unwrap();

        let mut unknown = template_id;
        unknown[15] ^= 1;
        assert_eq!(
            slot.begin_proving(unknown, now, 11, [3u8; 32]),
            Err(ExternalMiningConsumeError::Unavailable)
        );
        assert_eq!(
            slot.begin_proving(template_id, now, 11, [3u8; 32]),
            Ok("prepared")
        );
        assert!(slot.reserve_preparation(now).is_err());
        slot.finish_proving(template_id);
        assert!(slot.reserve_preparation(now).is_ok());
    }

    #[test]
    fn external_mining_slot_drops_expired_and_stale_ready_attempts() {
        let now = Instant::now();
        let mut slot = ExternalMiningAttemptSlot::new(9);
        let expired = slot.reserve_preparation(now).unwrap();
        slot.install_ready(expired, (), 4, [1u8; 32], now).unwrap();
        assert!(slot.reserve_preparation(now).is_ok());

        let active = match &slot.state {
            ExternalMiningAttemptState::Preparing { template_id, .. } => *template_id,
            _ => panic!("fresh reservation must be preparing"),
        };
        slot.install_ready(active, (), 5, [2u8; 32], now + Duration::from_secs(30))
            .unwrap();
        slot.invalidate_except(6, [4u8; 32]);
        assert_eq!(
            slot.begin_proving(active, now, 6, [4u8; 32]),
            Err(ExternalMiningConsumeError::Unavailable)
        );
        assert!(slot.reserve_preparation(now).is_ok());
    }

    #[test]
    fn canonical_advance_invalidates_preparing_but_keeps_proving_occupied() {
        let now = Instant::now();
        let mut slot = ExternalMiningAttemptSlot::new(11);
        let preparing = slot.reserve_preparation(now).unwrap();
        slot.invalidate_except(8, [8u8; 32]);
        assert!(slot
            .install_ready(preparing, (), 7, [7u8; 32], now + Duration::from_secs(30),)
            .is_err());
        let proving = slot.reserve_preparation(now).unwrap();
        slot.install_ready(proving, (), 8, [8u8; 32], now + Duration::from_secs(30))
            .unwrap();
        slot.begin_proving(proving, now, 8, [8u8; 32]).unwrap();
        slot.invalidate_except(9, [9u8; 32]);
        assert!(slot.reserve_preparation(now).is_err());
        slot.finish_proving(proving);
        assert!(slot.reserve_preparation(now).is_ok());
    }

    #[test]
    fn preparation_lease_drop_releases_only_its_own_token() {
        let attempts = ExternalMiningAttemptInvalidator::new();
        let first = attempts.reserve_preparation(Instant::now()).unwrap();
        assert!(attempts.reserve_preparation(Instant::now()).is_err());
        drop(first);
        let second = attempts.reserve_preparation(Instant::now()).unwrap();
        let second_id = second.template_id();
        let mut stale_id = second_id;
        stale_id[15] ^= 1;
        attempts.inner.lock().unwrap().cancel_preparation(stale_id);
        assert!(attempts.reserve_preparation(Instant::now()).is_err());
        drop(second);
        assert!(attempts.reserve_preparation(Instant::now()).is_ok());
    }

    #[test]
    fn proving_lease_drop_releases_the_occupied_slot() {
        let attempts = ExternalMiningAttemptInvalidator::new();
        let mut preparation = attempts.reserve_preparation(Instant::now()).unwrap();
        let template_id = preparation.template_id();
        attempts.inner.lock().unwrap().state = ExternalMiningAttemptState::Proving { template_id };
        preparation.armed = false;
        drop(preparation);

        let proving = ExternalMiningProvingLease {
            attempts: attempts.clone(),
            template_id,
        };
        assert!(attempts.reserve_preparation(Instant::now()).is_err());
        drop(proving);
        assert!(attempts.reserve_preparation(Instant::now()).is_ok());
    }

    #[test]
    fn transaction_count_validation_matches_paged_spend() {
        assert!(validate_tx_counts(1, 1).is_ok());
        assert!(validate_tx_counts(
            noid_tx::MAX_PAGED_SPEND_INPUTS,
            noid_tx::MAX_PAGED_SPEND_OUTPUTS,
        )
        .is_ok());
        assert!(validate_tx_counts(0, 1).is_err());
        assert!(validate_tx_counts(noid_tx::MAX_PAGED_SPEND_INPUTS + 1, 1).is_err());
        assert!(validate_tx_counts(1, noid_tx::MAX_PAGED_SPEND_OUTPUTS + 1).is_err());
    }

    #[test]
    fn mempool_status_exposes_the_exact_b64_b255_boundary() {
        let metadata = |page_count| noid_mempool::MempoolEntryMetadata {
            tx_hash: noid_poseidon2b::primitives::TxBodyHash([page_count as u8; 32]),
            fee_micronoid: 7,
            fee_rate: 3,
            n_inputs: 1,
            n_outputs: 1,
            page_count,
            admitted_height: 11,
            has_authorization: true,
        };

        let b64 = mempool_tx_info(metadata(64));
        assert_eq!(b64.page_count, 64);
        assert_eq!(b64.minimum_proof_class, "B64");
        assert!(!b64.requires_b255_miner);

        let b255 = mempool_tx_info(metadata(65));
        assert_eq!(b255.page_count, 65);
        assert_eq!(b255.minimum_proof_class, "B255");
        assert!(b255.requires_b255_miner);
    }

    #[test]
    fn input_limit_error_exposes_only_the_canonical_limit() {
        let error = wallet_plan_error(WalletSendPlanError::InputLimitExceeded { max_inputs: 8 });

        assert_eq!(error.code(), WALLET_INPUT_LIMIT_EXCEEDED_CODE);
        assert_eq!(error.message(), WALLET_INPUT_LIMIT_EXCEEDED_MESSAGE);
        let data: WalletInputLimitExceeded = serde_json::from_str(
            error
                .data()
                .expect("input-limit error has structured data")
                .get(),
        )
        .expect("input-limit error data decodes");
        assert_eq!(data.max_inputs, 8);
        let value = serde_json::to_value(data).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 1);
    }

    #[test]
    fn block_template_response_serializes_canonical_counts() {
        let response = BlockTemplateResponse {
            template_id: "00112233445566778899aabbccddeeff".into(),
            pow_fields_hex: "00".into(),
            nonce_field_index: POW_NONCE_FIELD_INDEX,
            difficulty_target_hex: "ff".into(),
            height: 7,
            expires_in_seconds: 30,
            n_txs: 3,
            tx_input_counts: vec![2, 5],
            tx_output_counts: vec![2, 1],
            coinbase_value_micronoid: 50,
            claimable_fees_micronoid: 9,
        };

        let json = serde_json::to_value(response).expect("serialize template response");
        assert_eq!(json["tx_input_counts"][1], 5);
        assert_eq!(json["template_id"], "00112233445566778899aabbccddeeff");
        assert_eq!(json["nonce_field_index"], POW_NONCE_FIELD_INDEX);
        assert_eq!(json["expires_in_seconds"], 30);
        assert_eq!(json.as_object().unwrap().len(), 11);
    }

    #[test]
    fn external_nonce_is_exact_canonical_little_endian_u128() {
        let bytes = [
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
            0x23, 0x01,
        ];
        let encoded = hex::encode(bytes);
        assert_eq!(
            decode_external_nonce_hex(&encoded).unwrap(),
            0x0123_4567_89ab_cdef_0123_4567_89ab_cdef
        );
        assert!(decode_external_nonce_hex(&encoded.to_uppercase()).is_err());
        assert!(decode_external_nonce_hex(&format!("0x{encoded}")).is_err());
        assert!(decode_external_nonce_hex(&encoded[..30]).is_err());
    }
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Start the JSON-RPC server and return a handle.
///
/// The server runs until `handle.stop()` is called or it is dropped.
/// Start the RPC server and return (handle, stop_rx).
/// `stop_rx` fires when `paranoid_stop` is called via RPC.
#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server(
    listen: SocketAddr,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    wallet: Arc<dyn WalletOps + Send + Sync>,
    wallet_operation_gate: WalletOperationGate,
    p2p_cmd: tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    history_step_runtime: Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
    history_step_ghost: Option<
        Arc<noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization>,
    >,
    external_mining_attempts: ExternalMiningAttemptInvalidator,
    mining_api_enabled: bool,
    mining_payout_address: Option<noid_poseidon2b::primitives::Address>,
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
        wallet_operation_gate,
        p2p_cmd,
        stop_tx,
        mining_api_enabled,
        mining_payout_address,
        mining_key: mining_key.clone(),
        allow_custom_coinbase,
        history_step_runtime,
        history_step_ghost,
        external_mining_attempts,
        external_mining_capacity: Arc::new(Mutex::new(AdaptiveProofCapacity::default())),
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
            return Box::pin(fut);
        };

        let auth = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if auth == expected {
            let fut = self.inner.call(req);
            Box::pin(fut)
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
