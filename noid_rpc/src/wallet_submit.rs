// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared wallet maintenance submission pipeline.
//!
//! Manual RPC consolidation and proactive default-miner consolidation use this
//! exact coordinator. It owns the long-lived operation gate from verified
//! active-owner reload through normal mempool admission, so neither path can
//! race a send/account switch or bypass authorization and admission checks.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};

use noid_chain::consensus::allocator::generate_slot_hints;
use noid_chain::consensus::pow::block_id;
use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;
use tokio::sync::{Mutex, RwLock};

use crate::types::WalletSendResult;
use crate::wallet_ops::WalletOps;

pub type WalletOperationGate = Arc<Mutex<()>>;

type CanonicalTip = (u64, [u8; 32]);

#[derive(Default)]
struct ProactiveAdmissionLatch {
    admitted_tip: StdMutex<Option<CanonicalTip>>,
}

impl ProactiveAdmissionLatch {
    fn contains(&self, tip: CanonicalTip) -> bool {
        let admitted = self
            .admitted_tip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *admitted == Some(tip)
    }

    fn mark(&self, tip: CanonicalTip) {
        *self
            .admitted_tip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tip);
    }
}

/// Owned wallet reservation around an async admission future. Dropping the
/// future at any await point synchronously rolls back inputs, outputs, and the
/// pending history record. `commit` disarms it after successful admission.
pub(crate) struct PendingAdmissionGuard {
    rollback: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl PendingAdmissionGuard {
    fn armed(rollback: impl FnOnce() + Send + 'static) -> Self {
        Self {
            rollback: Some(Box::new(rollback)),
        }
    }

    pub(crate) fn reserve(
        wallet: Arc<dyn WalletOps + Send + Sync>,
        txid: [u8; 32],
        input_slots: Vec<u32>,
        output_slots: Vec<u32>,
        amount_micronoid: u64,
        peer_address: [u8; 32],
    ) -> Result<Self, String> {
        wallet.reserve_pending_submission(
            txid,
            &input_slots,
            &output_slots,
            amount_micronoid,
            peer_address,
        )?;
        Ok(Self::armed(move || {
            wallet.rollback_pending_submission(txid, &input_slots, &output_slots);
        }))
    }

    pub(crate) fn commit(mut self) {
        self.rollback = None;
    }
}

impl Drop for PendingAdmissionGuard {
    fn drop(&mut self) {
        if let Some(rollback) = self.rollback.take() {
            rollback();
        }
    }
}

#[derive(Clone)]
pub struct WalletSubmitCoordinator {
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    wallet: Arc<dyn WalletOps + Send + Sync>,
    gate: WalletOperationGate,
    proactive_latch: Arc<ProactiveAdmissionLatch>,
}

impl WalletSubmitCoordinator {
    pub fn new(
        chain: Arc<RwLock<MdbxChainContext>>,
        mempool: AsyncMempool,
        wallet: Arc<dyn WalletOps + Send + Sync>,
        gate: WalletOperationGate,
    ) -> Self {
        Self {
            chain,
            mempool,
            wallet,
            gate,
            proactive_latch: Arc::new(ProactiveAdmissionLatch::default()),
        }
    }

    pub fn operation_gate(&self) -> WalletOperationGate {
        Arc::clone(&self.gate)
    }

    async fn reload_active_wallet(&self) -> Result<(), String> {
        let preview = self.wallet.preview_active_reload()?;
        let (reserved_inputs, reserved_outputs) = self.mempool.reserved_slots().await;
        let chain = self.chain.read().await;
        let snapshot = chain
            .store
            .get_verified_utxos_by_owner(&preview.owner)
            .map_err(|error| error.to_string())?;
        self.wallet.commit_activation_snapshot(
            preview,
            snapshot,
            &reserved_inputs,
            &reserved_outputs,
        )?;
        Ok(())
    }

    /// Submit one ordinary active-owner `8 -> 1`-capable self-payment.
    ///
    /// `minimum_inputs = 2` is the explicit RPC operation. `8` is proactive
    /// miner maintenance and returns `Ok(None)` until a full round is ready.
    pub async fn submit_consolidation(
        &self,
        minimum_inputs: usize,
        requested_fee_micronoid: u64,
    ) -> Result<Option<WalletSendResult>, String> {
        if !(2..=noid_tx::TX_INPUTS).contains(&minimum_inputs) {
            return Err("invalid consolidation threshold".to_string());
        }

        let _operation = self.gate.lock().await;
        let proactive = minimum_inputs == noid_tx::TX_INPUTS;
        if proactive {
            let tip = {
                let chain = self.chain.read().await;
                (chain.tip_height, block_id(chain.tip_header()))
            };
            if self.proactive_latch.contains(tip) {
                return Ok(None);
            }
        }
        self.reload_active_wallet().await?;
        let planned_inputs = match self.wallet.plan_consolidate_input_count() {
            Ok(count) if count >= minimum_inputs => count,
            Ok(_) if minimum_inputs == noid_tx::TX_INPUTS => return Ok(None),
            Ok(_) => return Err("nothing to consolidate".to_string()),
            Err(_) if minimum_inputs == noid_tx::TX_INPUTS => return Ok(None),
            Err(error) => return Err(error),
        };

        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let relay_floor = self.mempool.fee_floor().await;
        let breakdown = noid_chain::consensus::fee_breakdown(
            planned_inputs as u64,
            1,
            active_slot_count,
            log_slots,
        );
        let minimum_fee = breakdown.required_total.max(relay_floor);
        let fee = if requested_fee_micronoid == 0 {
            minimum_fee
        } else {
            requested_fee_micronoid
        };
        if fee < minimum_fee {
            return Err(format!(
                "BelowMinFee: consolidation fee {fee} μNOID is below required {minimum_fee} μNOID"
            ));
        }

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
            let (epoch_anchor, slot_hints, log_slots) = {
                let chain = self.chain.read().await;
                let tip = chain.tip_header();
                let unique_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap())
                    .wrapping_add(
                        call_nonce
                            .wrapping_add(attempt as u64)
                            .wrapping_mul(0x9e37_79b9_7f4a_7c15),
                    );
                let hints =
                    collect_empty_slot_hints(&chain, &reserved_outputs, unique_seed, 1, 256)?;
                (next_user_epoch_anchor(&chain)?, hints, tip.log_slots)
            };
            if slot_hints.is_empty() {
                return Err("no empty output slot available".to_string());
            }

            let wallet = Arc::clone(&self.wallet);
            let (intent_bytes, input_slots) = tokio::task::spawn_blocking(move || {
                wallet.build_consolidate(fee, epoch_anchor, slot_hints, log_slots)
            })
            .await
            .map_err(|error| format!("consolidation task: {error}"))??;
            let intent = noid_tx::TxIntent::from_bytes(&intent_bytes)
                .map_err(|error| format!("intent decode: {error:?}"))?;
            let input_count = intent.tx_body.live_input_count();
            let output_count = intent.tx_body.live_output_count();
            let actual_fee = intent.tx_body.fee;
            let amount_micronoid = intent
                .tx_body
                .live_outputs()
                .map(|(_, output)| output.amount)
                .try_fold(0u64, u64::checked_add)
                .ok_or_else(|| "consolidation output amount overflow".to_string())?;
            let failed_txid = intent.txid().0;
            let output_slots: Vec<u32> = intent
                .tx_body
                .live_outputs()
                .map(|(_, output)| output.slot_index)
                .collect();

            let reservation = PendingAdmissionGuard::reserve(
                Arc::clone(&self.wallet),
                failed_txid,
                input_slots,
                output_slots,
                actual_fee,
                intent.tx_body.input_owner.0,
            )?;
            match self
                .mempool
                .submit_local_consolidation(intent, intent_bytes)
                .await
            {
                Ok(txid) => {
                    reservation.commit();
                    if proactive {
                        let admitted_tip = {
                            let chain = self.chain.read().await;
                            (chain.tip_height, block_id(chain.tip_header()))
                        };
                        self.proactive_latch.mark(admitted_tip);
                    }
                    return Ok(Some(WalletSendResult {
                        txid: hex::encode(txid.0),
                        amount_micronoid,
                        fee_micronoid: actual_fee,
                        input_count,
                        output_count,
                    }));
                }
                Err(error) => {
                    drop(reservation);
                    last_error = error.to_string();
                }
            }
        }

        Err(format!(
            "consolidation failed after 3 attempts: {last_error}"
        ))
    }
}

/// Select exact empty slots without treating an evicted live segment as a
/// virtual zero segment. Missing/corrupt durable segment data fails closed.
pub(crate) fn collect_empty_slot_hints(
    chain: &MdbxChainContext,
    reserved: &HashSet<u32>,
    seed: u64,
    count: usize,
    fallback_candidates: usize,
) -> Result<Vec<u32>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let state = &chain.state.state;
    let mut hints = state.empty_slot_hints_in_populated_segments(seed, count, reserved);
    if hints.len() == count {
        return Ok(hints);
    }

    let mut seen = reserved.clone();
    seen.extend(hints.iter().copied());
    let mut segment_cache = HashMap::new();
    for index in generate_slot_hints(seed, state.log_slots() as u32, fallback_candidates) {
        if u64::from(index) >= state.num_slots() || !seen.insert(index) {
            continue;
        }
        if read_exact_slot(chain, index, &mut segment_cache)?
            == noid_chain::fri_state::SlotValue::EMPTY
        {
            hints.push(index);
            if hints.len() == count {
                break;
            }
        }
    }
    Ok(hints)
}

fn read_exact_slot(
    chain: &MdbxChainContext,
    slot_index: u32,
    segment_cache: &mut HashMap<u16, noid_chain::segmented_state::SegmentColumns>,
) -> Result<noid_chain::fri_state::SlotValue, String> {
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
    Ok(noid_chain::fri_state::SlotValue {
        value: columns.values[local_index],
        owner_hi: columns.owners_hi[local_index],
        owner_lo: columns.owners_lo[local_index],
    })
}

/// Resolve the sole user-transaction anchor accepted in the next child block.
/// Durable lookup is required because it can be 144 blocks behind the tip.
pub fn next_user_epoch_anchor(chain: &MdbxChainContext) -> Result<[u8; 32], String> {
    let child_height = chain
        .tip_height
        .checked_add(1)
        .ok_or_else(|| "child height overflow".to_string())?;
    let anchor_height = noid_chain::consensus::tx_epoch_anchor_height_for_child(child_height);
    let header = chain
        .get_header_from_store(anchor_height)
        .map_err(|error| format!("load transaction epoch anchor: {error}"))?
        .ok_or_else(|| "canonical transaction epoch anchor header is missing".to_string())?;
    Ok(block_id(&header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn pending_guard_rolls_back_on_drop_and_disarms_on_commit() {
        let rollbacks = Arc::new(AtomicUsize::new(0));
        {
            let rollbacks = Arc::clone(&rollbacks);
            let _guard = PendingAdmissionGuard::armed(move || {
                rollbacks.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert_eq!(rollbacks.load(Ordering::SeqCst), 1);

        {
            let rollbacks = Arc::clone(&rollbacks);
            PendingAdmissionGuard::armed(move || {
                rollbacks.fetch_add(1, Ordering::SeqCst);
            })
            .commit();
        }
        assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn aborting_admission_future_drops_the_armed_reservation() {
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let task_rollbacks = Arc::clone(&rollbacks);
        let task = tokio::spawn(async move {
            let _guard = PendingAdmissionGuard::armed(move || {
                task_rollbacks.fetch_add(1, Ordering::SeqCst);
            });
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn proactive_latch_is_shared_and_scoped_to_exact_parent() {
        let latch = Arc::new(ProactiveAdmissionLatch::default());
        let clone = Arc::clone(&latch);
        let parent_a = (7, [0xAA; 32]);
        let parent_b = (7, [0xBB; 32]);
        assert!(!latch.contains(parent_a));
        latch.mark(parent_a);
        assert!(clone.contains(parent_a));
        assert!(!clone.contains(parent_b));
    }
}
