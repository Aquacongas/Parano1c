// SPDX-License-Identifier: Apache-2.0

//! Local full-node wallet submission.
//!
//! No RPC Push/Pull path exists here:
//!
//! wallet build/prove
//! -> wallet reservation
//! -> local authoritative mempool submit
//! -> reservation commit
//! -> MempoolEvent::TxAdmitted
//! -> P2P relay

use std::sync::Arc;

use anyhow::{anyhow, Result};

use noid_wallet::submit::{
    build_send, collect_empty_slot_hints, next_user_epoch_anchor, plan_send, PendingAdmissionGuard,
    WalletSendPlan,
};

use crate::MobileNodeRuntime;

#[derive(Debug, Clone)]
pub struct MobileSendResult {
    pub txid: [u8; 32],
    pub amount_micronoid: u64,
    pub fee_micronoid: u64,
    pub input_count: usize,
    pub output_count: usize,
}

impl MobileNodeRuntime {
    /// Build, prove, reserve and admit one payment directly into this node's
    /// authoritative local mempool.
    ///
    /// `fee_micronoid == 0` selects the current deterministic automatic fee.
    pub async fn send(
        &self,
        to_address: [u8; 32],
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> Result<MobileSendResult> {
        // Same gate used by exact chain/reorg wallet mutation.
        let _operation = self.apply_gate.lock().await;

        // ------------------------------------------------------------
        // Refresh the active wallet from exact canonical MDBX before
        // planning. Do not build from an old pre-reorg wallet cache.
        // ------------------------------------------------------------

        {
            let (reserved_inputs, reserved_outputs) = self.mempool.reserved_slots().await;

            let chain = self.chain.read().await;

            let (active_index, next_index, owner) = {
                let guard = self
                    .wallet
                    .lock()
                    .map_err(|_| anyhow!("wallet state lock is poisoned"))?;

                let state = guard
                    .as_ref()
                    .ok_or_else(|| anyhow!("wallet not initialized"))?;

                (
                    state.active_index,
                    state.next_index,
                    state.active_address().0,
                )
            };

            let snapshot = chain
                .store
                .get_verified_utxos_by_owner(&owner)
                .map_err(|error| anyhow!("{error}"))?;

            {
                let mut guard = self
                    .wallet
                    .lock()
                    .map_err(|_| anyhow!("wallet state lock is poisoned"))?;

                let state = guard
                    .as_mut()
                    .ok_or_else(|| anyhow!("wallet not initialized"))?;

                state
                    .commit_verified_activation(
                        active_index,
                        next_index,
                        active_index,
                        owner,
                        snapshot,
                        &reserved_inputs,
                        &reserved_outputs,
                    )
                    .map_err(|error| anyhow!("{error}"))?;
            }
        }

        // ------------------------------------------------------------
        // Deterministic fee/input/output plan.
        // ------------------------------------------------------------

        let (active_slot_count, log_slots) = self.mempool.fee_context().await;

        let relay_floor = self.mempool.fee_floor().await;

        let plan = plan_send(
            &self.wallet,
            amount_micronoid,
            (fee_micronoid != 0).then_some(fee_micronoid),
            active_slot_count,
            log_slots,
            relay_floor,
        )
        .map_err(|error| anyhow!("{error}"))?;

        tracing::info!(
            amount_micronoid,
            fee_micronoid = plan.fee_micronoid,
            input_count = plan.input_count,
            output_count = plan.output_count,
            "mobile local-send plan ready"
        );

        let call_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;

        let mut last_error = String::new();

        // Same bounded retry policy as desktop wallet submission.
        for attempt in 0..3u32 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }

            let reserved_outputs = self.mempool.reserved_output_slots().await;

            let (epoch_anchor, build_log_slots, slot_hints) = {
                let chain = self.chain.read().await;

                let tip = chain.tip_header();

                let unique_seed =
                    u64::from_le_bytes(tip.state_root[..8].try_into().expect("state root prefix"))
                        .wrapping_add(
                            call_nonce
                                .wrapping_add(attempt as u64)
                                .wrapping_mul(0x9e37_79b9_7f4a_7c15),
                        );

                let epoch_anchor =
                    next_user_epoch_anchor(&chain).map_err(|error| anyhow!("{error}"))?;

                let hints = collect_empty_slot_hints(
                    &chain,
                    &reserved_outputs,
                    unique_seed,
                    noid_tx::TX_OUTPUTS,
                )
                .map_err(|error| anyhow!("{error}"))?;

                (epoch_anchor, tip.log_slots, hints)
            };

            if slot_hints.len() < plan.output_count {
                last_error = "not enough empty output slots available".to_string();
                break;
            }

            // --------------------------------------------------------
            // Heavy wallet proof OUTSIDE wallet mutex.
            // --------------------------------------------------------

            let wallet = Arc::clone(&self.wallet);

            let fee = plan.fee_micronoid;

            let build = tokio::task::spawn_blocking(move || {
                build_send(
                    &wallet,
                    to_address,
                    amount_micronoid,
                    fee,
                    epoch_anchor,
                    slot_hints,
                    build_log_slots,
                )
            })
            .await;

            let (intent_bytes, input_slots) = match build {
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

            // --------------------------------------------------------
            // Decode and independently validate builder output.
            // --------------------------------------------------------

            let intent = match noid_tx::PagedSpendIntent::from_bytes(&intent_bytes) {
                Ok(intent) => intent,

                Err(error) => {
                    last_error = format!("intent decode: {error:?}");
                    break;
                }
            };

            let facts = noid_tx::validate_paged_spend(&intent.pages)
                .map_err(|error| anyhow!("wallet PagedSpend: {error}"))?;

            let input_count = usize::from(facts.live_inputs);

            let output_count = usize::from(facts.live_outputs);

            let actual_fee = facts.fee;

            if actual_fee != plan.fee_micronoid
                || input_count != plan.input_count
                || output_count != plan.output_count
            {
                return Err(anyhow!(
                    "wallet builder diverged from plan: expected fee/counts {}/{}/{}, got {}/{}/{}",
                    plan.fee_micronoid,
                    plan.input_count,
                    plan.output_count,
                    actual_fee,
                    input_count,
                    output_count,
                ));
            }

            let txid = facts.logical_txid.0;

            let output_slots = intent
                .pages
                .iter()
                .flat_map(|page| page.body.live_outputs())
                .map(|(_, output)| output.slot_index)
                .collect::<Vec<_>>();

            // --------------------------------------------------------
            // Cancellation-safe wallet reservation.
            // --------------------------------------------------------

            let reservation = PendingAdmissionGuard::reserve(
                Arc::clone(&self.wallet),
                txid,
                input_slots,
                output_slots,
                amount_micronoid,
                to_address,
            )
            .map_err(|error| anyhow!("{error}"))?;

            // --------------------------------------------------------
            // AUTHORITATIVE LOCAL MEMPOOL ADMISSION.
            //
            // No remote ACK/Pull path.
            // --------------------------------------------------------

            match self.mempool.submit(intent, intent_bytes).await {
                Ok(admitted_txid) => {
                    reservation.commit();

                    if attempt > 0 {
                        tracing::info!(attempt, "mobile wallet submission succeeded after retry");
                    }

                    return Ok(MobileSendResult {
                        txid: admitted_txid.0,
                        amount_micronoid,
                        fee_micronoid: actual_fee,
                        input_count,
                        output_count,
                    });
                }

                Err(error) => {
                    // Drop guard => rollback inputs, outputs and pending history.
                    drop(reservation);

                    last_error = error.to_string();
                }
            }
        }

        Err(anyhow!("wallet send failed after 3 attempts: {last_error}"))
    }

    pub async fn plan_send(
        &self,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> Result<WalletSendPlan> {
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;

        let relay_floor = self.mempool.fee_floor().await;

        noid_wallet::submit::plan_send(
            &self.wallet,
            amount_micronoid,
            (fee_micronoid != 0).then_some(fee_micronoid),
            active_slot_count,
            log_slots,
            relay_floor,
        )
        .map_err(|error| anyhow!("{error}"))
    }
}
