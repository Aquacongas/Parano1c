// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use libp2p::PeerId;
use tokio::sync::{Mutex, RwLock};

use noid_chain::storage::MdbxChainContext;
use noid_mempool::{AsyncMempool, ChainView};
use noid_networking::{suffix_sync::FetchedSuffix, sync_plan::SyncPlanKind};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_wallet::SharedWallet;

pub type HistoryStepRuntime = noid_recursive::acceptance::history_step::HistoryStepRuntime;

pub struct AppliedCompactSuffix {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub confirmed_tx_hashes: Vec<TxBodyHash>,
    pub view: ChainView,
    pub applied_blocks: u64,
    pub payload_bytes: u64,
    pub apply_elapsed: Duration,
    pub trailing_error: Option<ExactSuffixApplyError>,
}

pub struct AppliedReorg {
    pub result: noid_chain::consensus::ReorgResult,
    pub confirmed_tx_hashes: Vec<TxBodyHash>,
    pub view: ChainView,
}

pub enum AppliedExactSuffix {
    Live(AppliedCompactSuffix),
    Reorg(AppliedReorg),
}

#[derive(Debug)]
pub enum ExactSuffixApplyError {
    Terminal { source: PeerId, error: String },
    Body { sources: Vec<PeerId>, error: String },
    Other(String),
}

impl ExactSuffixApplyError {
    fn terminal(source: PeerId, error: impl Into<String>) -> Self {
        Self::Terminal {
            source,
            error: error.into(),
        }
    }

    fn body(source: PeerId, error: impl Into<String>) -> Self {
        Self::Body {
            sources: vec![source],
            error: error.into(),
        }
    }
}

impl std::fmt::Display for ExactSuffixApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminal { error, .. } | Self::Body { error, .. } | Self::Other(error) => {
                f.write_str(error)
            }
        }
    }
}

impl std::error::Error for ExactSuffixApplyError {}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn verify_history_step_terminal(
    claim: &noid_chain::storage::HistoryStepTerminalClaim<'_>,
    runtime: Option<&HistoryStepRuntime>,
) -> Result<(), String> {
    let Some(runtime) = runtime else {
        return Err("embedded HistoryStep verifier unavailable".to_string());
    };

    // Same recursive verification used by the full node.
    // Mobile deliberately does NOT depend on noid_miner merely for
    // install_inbound_verifier_cpu().
    noid_recursive::acceptance::history_step::decode_verify_history_step_terminal(
        runtime,
        claim.terminal_bytes,
        &claim.header,
        &claim.epoch_anchor_header,
    )
    .map(|_| ())
    .map_err(|error| format!("HistoryStep terminal rejected: {error}"))
}

fn history_step_error_is_peer_fault(error: &noid_chain::storage::MdbxContextError) -> bool {
    match error {
        noid_chain::storage::MdbxContextError::Consensus(
            noid_chain::consensus::ConsensusError::BadHistoryStepTerminal(message),
        ) => {
            message.contains("terminal exceeds the wire cap")
                || message.contains("terminal metadata is invalid")
                || message.contains("terminal does not bind")
                || message.contains("HistoryStep terminal rejected:")
        }

        _ => false,
    }
}

fn body_error_is_peer_fault(error: &noid_chain::storage::MdbxContextError) -> bool {
    match error {
        noid_chain::storage::MdbxContextError::Consensus(_) => true,

        noid_chain::storage::MdbxContextError::Corrupt(message) => {
            matches!(
                *message,
                "recursive suffix block body is malformed"
                    | "recursive suffix block has invalid logical transactions"
                    | "recursive reorg body is malformed"
                    | "recursive reorg tip body is malformed"
            )
        }

        noid_chain::storage::MdbxContextError::Store(_)
        | noid_chain::storage::MdbxContextError::ResourceLimit { .. } => false,
    }
}

/// Shared exact-suffix apply backend.
///
/// Consensus/storage semantics match full node:
///
/// FetchedSuffix
/// → decode bodies
/// → body/header binding
/// → HistoryStep terminal verification
/// → writer admission
/// → live suffix OR atomic reorg
/// → mempool canonical-state update
pub async fn apply_exact_suffix(
    chain: &Arc<RwLock<MdbxChainContext>>,
    mempool: &AsyncMempool,
    wallet: &SharedWallet,
    fetched: FetchedSuffix,
    history_step_runtime: Option<Arc<HistoryStepRuntime>>,
    operation_gate: &Mutex<()>,
) -> Result<AppliedExactSuffix, ExactSuffixApplyError> {
    let _operation = operation_gate.lock().await;

    let (reserved_input_slots, reserved_output_slots) = mempool.reserved_slots().await;

    let apply_wallet = Arc::clone(wallet);

    let apply_chain = Arc::clone(chain);

    let apply_store = {
        let ctx = chain.read().await;
        ctx.store.clone()
    };

    let result = tokio::task::spawn_blocking(move || {
        let (plan, body_bytes, body_sources, terminal_bytes, terminal_source, inbound_permits) =
            fetched.into_parts();

        let _inbound_permits = inbound_permits;

        if body_bytes.len() != plan.headers().len()
            || body_sources.len() != body_bytes.len()
            || body_bytes.is_empty()
        {
            return Err(ExactSuffixApplyError::Other(
                "exact suffix body/source count differs from its immutable plan".into(),
            ));
        }

        let mut blocks = Vec::with_capacity(body_bytes.len());

        for ((bytes, source), expected) in body_bytes.iter().zip(&body_sources).zip(plan.headers())
        {
            let block = noid_chain::Block::from_bytes(bytes).map_err(|error| {
                ExactSuffixApplyError::body(*source, format!("decode exact suffix body: {error:?}"))
            })?;

            if block.header != expected.header {
                return Err(ExactSuffixApplyError::body(
                    *source,
                    "exact suffix body header differs from its validated header",
                ));
            }

            blocks.push(block);
        }

        let tip_header = blocks
            .last()
            .expect("non-empty suffix checked above")
            .header;

        if noid_chain::block_id(&tip_header) != plan.target().hash {
            return Err(ExactSuffixApplyError::body(
                *body_sources.last().expect("non-empty source list"),
                "exact suffix bodies do not end at selected target",
            ));
        }

        let epoch_height =
            noid_chain::consensus::tx_epoch_anchor_height_for_child(tip_header.height);

        let epoch_anchor_header = if epoch_height <= plan.base().height {
            apply_store
                .get_header(epoch_height)
                .map_err(|error| {
                    ExactSuffixApplyError::Other(format!("load exact suffix epoch anchor: {error}"))
                })?
                .ok_or_else(|| {
                    ExactSuffixApplyError::Other(
                        "exact suffix epoch anchor missing from canonical storage".into(),
                    )
                })?
        } else {
            blocks
                .iter()
                .find(|block| block.header.height == epoch_height)
                .map(|block| block.header)
                .ok_or_else(|| {
                    ExactSuffixApplyError::Other(
                        "exact suffix epoch anchor missing from candidate bodies".into(),
                    )
                })?
        };

        let terminal_started = Instant::now();

        let verified_terminal = noid_chain::storage::verify_history_step_terminal_candidate(
            tip_header,
            epoch_anchor_header,
            terminal_bytes,
            |claim| verify_history_step_terminal(claim, history_step_runtime.as_deref()),
        )
        .map_err(|error| {
            let message = format!("verify exact suffix terminal: {error}");

            if history_step_error_is_peer_fault(&error) {
                ExactSuffixApplyError::terminal(terminal_source, message)
            } else {
                ExactSuffixApplyError::Other(message)
            }
        })?;

        tracing::info!(
            height = tip_header.height,
            elapsed_ms = terminal_started.elapsed().as_millis(),
            "mobile exact suffix terminal verified"
        );

        let writer_started = Instant::now();
        let mut ctx = apply_chain.blocking_write();

        if writer_started.elapsed() >= Duration::from_secs(2) {
            tracing::warn!(
                target_height = plan.target().height,
                "mobile exact suffix waited for chain writer"
            );
        }

        match plan.kind() {
            SyncPlanKind::LiveSuffix => {
                if ctx.tip_height() != plan.base().height || ctx.tip_hash() != plan.base().hash {
                    return Err(ExactSuffixApplyError::Other(
                        "exact live suffix base changed before commit".into(),
                    ));
                }

                let mut authority = ctx
                    .begin_preverified_recursive_suffix(verified_terminal)
                    .map_err(|error| {
                        let message = format!("authorize exact live suffix terminal: {error}");

                        if history_step_error_is_peer_fault(&error) {
                            ExactSuffixApplyError::terminal(terminal_source, message)
                        } else {
                            ExactSuffixApplyError::Other(message)
                        }
                    })?;

                let started = Instant::now();

                let payload_bytes = body_bytes
                    .iter()
                    .fold(0u64, |sum, bytes| sum.saturating_add(bytes.len() as u64));

                let mut confirmed_tx_hashes = Vec::new();
                let mut applied_blocks = 0u64;
                let mut trailing_error = None;

                for ((block, bytes), source) in blocks.iter().zip(&body_bytes).zip(&body_sources) {
                    let txids = match noid_chain::try_compute_logical_txids(&block.transactions) {
                        Ok(txids) => txids,

                        Err(error) => {
                            trailing_error = Some(ExactSuffixApplyError::body(
                                *source,
                                format!("exact suffix logical transaction stream: {error}"),
                            ));

                            break;
                        }
                    };

                    if let Err(error) = ctx.apply_verified_recursive_suffix_block(
                        &mut authority,
                        bytes,
                        unix_now(),
                        |block, state| {
                            noid_chain::materialize_accepted_block_state(state, block)
                                .map_err(|error| format!("{error:?}"))
                        },
                    ) {
                        let message =
                            format!("apply exact suffix block {}: {error}", block.header.height);

                        trailing_error = Some(if body_error_is_peer_fault(&error) {
                            ExactSuffixApplyError::body(*source, message)
                        } else {
                            ExactSuffixApplyError::Other(message)
                        });

                        break;
                    }

                    if let Err(error) = noid_wallet::update_for_accepted_block(&apply_wallet, block)
                    {
                        tracing::error!(
                            height = block.header.height,
                            %error,
                            "post-commit mobile wallet block update failed"
                        );
                    }

                    confirmed_tx_hashes.extend(txids);
                    applied_blocks = applied_blocks.saturating_add(1);
                }

                if trailing_error.is_none() && !authority.is_complete() {
                    trailing_error = Some(ExactSuffixApplyError::Other(
                        "exact suffix ended before verified tip".into(),
                    ));
                }

                let view = ChainView::from_mdbx(&ctx);

                Ok(AppliedExactSuffix::Live(AppliedCompactSuffix {
                    height: ctx.tip_height(),
                    block_hash: ctx.tip_hash(),
                    confirmed_tx_hashes,
                    view,
                    applied_blocks,
                    payload_bytes,
                    apply_elapsed: started.elapsed(),
                    trailing_error,
                }))
            }

            SyncPlanKind::Reorg => {
                let authority = ctx
                    .authorize_preverified_reorg_suffix(plan.base().height, verified_terminal)
                    .map_err(|error| {
                        let message = format!("authorize exact reorg terminal: {error}");

                        if history_step_error_is_peer_fault(&error) {
                            ExactSuffixApplyError::terminal(terminal_source, message)
                        } else {
                            ExactSuffixApplyError::Other(message)
                        }
                    })?;

                let reorg = ctx
                    .apply_verified_reorg_suffix_with_applier_indexed(
                        authority,
                        &body_bytes,
                        unix_now(),
                        |block, state| {
                            noid_chain::materialize_accepted_block_state(state, block)
                                .map_err(|error| format!("{error:?}"))
                        },
                    )
                    .map_err(|failure| {
                        let message = format!("apply atomic exact reorg suffix: {}", failure.error);

                        match failure.body_index {
                            Some(index) if body_error_is_peer_fault(&failure.error) => {
                                match body_sources.get(index).copied() {
                                    Some(source) => ExactSuffixApplyError::body(source, message),

                                    None => ExactSuffixApplyError::Other(message),
                                }
                            }

                            _ => ExactSuffixApplyError::Other(message),
                        }
                    })?;

                // ---------------------------------------------------------
                // WALLET REORG
                //
                // Never replay replacement blocks onto orphan-branch UTXOs.
                // Fetch one exact verified owner snapshot from canonical MDBX,
                // then rebuild only history/receipt artifacts from the
                // replacement block bodies.
                // ---------------------------------------------------------

                let selection = match apply_wallet.lock() {
                    Ok(guard) => guard.as_ref().map(|wallet| {
                        (
                            wallet.active_index,
                            wallet.next_index,
                            wallet.active_address().0,
                        )
                    }),

                    Err(_) => {
                        tracing::error!("wallet state lock poisoned after exact reorg");
                        None
                    }
                };

                if let Some((active_index, next_index, owner)) = selection {
                    match ctx.store.get_verified_utxos_by_owner(&owner) {
                        Ok(snapshot) => {
                            let block_refs = blocks.iter().collect::<Vec<_>>();

                            if let Err(error) = noid_wallet::install_reorg_snapshot_and_artifacts(
                                &apply_wallet,
                                active_index,
                                next_index,
                                owner,
                                snapshot,
                                &reserved_input_slots,
                                &reserved_output_slots,
                                &reorg.reclaimed_tx_hashes,
                                &block_refs,
                            ) {
                                tracing::error!(
                                    %error,
                                    "post-exact-reorg wallet snapshot install failed"
                                );

                                noid_wallet::invalidate_active_cache(&apply_wallet);
                            }
                        }

                        Err(error) => {
                            tracing::error!(
                                %error,
                                "post-exact-reorg canonical owner lookup failed"
                            );

                            noid_wallet::invalidate_active_cache(&apply_wallet);
                        }
                    }
                }

                let confirmed_tx_hashes = blocks
                    .iter()
                    .flat_map(|block| {
                        noid_chain::try_compute_logical_txids(&block.transactions)
                            .expect("committed reorg blocks have canonical transactions")
                    })
                    .collect();

                let view = ChainView::from_mdbx(&ctx);

                Ok(AppliedExactSuffix::Reorg(AppliedReorg {
                    result: reorg,
                    confirmed_tx_hashes,
                    view,
                }))
            }

            SyncPlanKind::Snapshot => Err(ExactSuffixApplyError::Other(
                "snapshot plan reached live suffix committer".into(),
            )),
        }
    })
    .await
    .map_err(|error| {
        ExactSuffixApplyError::Other(format!("exact suffix worker panicked: {error}"))
    })??;

    // ========================================================
    // POST-COMMIT MEMPOOL RECONCILIATION
    // ========================================================

    match &result {
        AppliedExactSuffix::Live(applied) if applied.applied_blocks != 0 => {
            mempool
                .on_new_block(
                    &applied.confirmed_tx_hashes,
                    applied.height,
                    applied.view.clone(),
                )
                .await;
        }

        AppliedExactSuffix::Reorg(applied) => {
            mempool
                .on_new_block(
                    &applied.confirmed_tx_hashes,
                    applied.view.tip_height,
                    applied.view.clone(),
                )
                .await;

            mempool
                .readmit_after_reorg(applied.result.reclaimed_tx_hashes.clone())
                .await;
        }

        AppliedExactSuffix::Live(_) => {}
    }

    Ok(result)
}
