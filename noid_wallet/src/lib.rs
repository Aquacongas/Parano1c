// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared wallet core used by full-node and mobile runtimes.
//!
//! Secret-bearing wallet code lives here so desktop and mobile use the
//! identical transaction builder, prover, scanner, keystore and state model.

pub mod builder;
pub mod keystore;
pub mod prover;
pub mod scanner;
pub mod state;
pub mod submit;

pub use state::{SharedWallet, WalletState};

// ===========================================================================
// Canonical-chain integration
// ===========================================================================

use noid_chain::storage::VerifiedOwnerSnapshot;

/// Apply one already-committed canonical block to the active wallet.
///
/// Caller holds the chain writer while this runs. The lock order is
/// `chain -> wallet`, which prevents wallet activation/reload from racing
/// an older canonical delta.
pub fn update_for_accepted_block(
    wallet: &SharedWallet,
    block: &noid_chain::block::Block,
) -> Result<(), String> {
    let mut guard = wallet
        .lock()
        .map_err(|_| "wallet state lock is poisoned".to_string())?;

    let Some(wallet) = guard.as_mut() else {
        return Ok(());
    };

    let history_count_before = wallet.history.len();
    let receipt_count_before = wallet.receipts.len();

    wallet.ensure_generated_address_index();

    let active_address = wallet.active_address();
    let active_index = wallet.active_index;

    scanner::update_active_wallet_from_block(
        &mut wallet.utxos,
        &mut wallet.history,
        &mut wallet.receipts,
        active_address,
        active_index,
        &mut wallet.pending_input_slots,
        block,
    )?;

    let walletwide_history_changed = scanner::update_walletwide_received_history_from_block(
        &mut wallet.history,
        &wallet.generated_address_index,
        block,
    )?;

    wallet.active_snapshot = Some(state::ActiveWalletSnapshot {
        height: block.header.height,
        tip_hash: noid_chain::consensus::pow::block_id(&block.header),
        state_root: block.header.state_root,
        log_slots: block.header.log_slots,
        active_slot_count: block.header.active_slot_count,
        alloc_counter: block.header.alloc_counter,
    });

    let mut history_changed =
        wallet.history.len() != history_count_before || walletwide_history_changed;

    let confirmed_block_hash = noid_chain::block_id(&block.header);

    for txid in noid_chain::try_compute_logical_txids(&block.transactions)
        .map_err(|error| format!("accepted block logical txids: {error}"))?
    {
        history_changed |=
            wallet.confirm_pending_tx(&txid.0, block.header.height, confirmed_block_hash);
    }

    for tx in &block.transactions {
        let output_slots: Vec<u32> = tx
            .body
            .live_outputs()
            .map(|(_, output)| output.slot_index)
            .collect();

        wallet.remove_pending_outputs(&output_slots);
    }

    if history_changed {
        wallet.mark_history_dirty();
    }

    if wallet.receipts.len() != receipt_count_before {
        wallet.mark_receipts_dirty();
    }

    if wallet.history_dirty() {
        wallet.save_history()?;
    }

    if wallet.receipts_dirty() {
        wallet.save_receipts()?;
    }

    Ok(())
}

/// Install the exact active-owner snapshot produced by the new canonical
/// branch after an atomic reorg.
///
/// UTXOs are NOT reconstructed by replaying replacement blocks onto the
/// orphaned wallet cache. MDBX supplies one verified canonical owner snapshot.
/// Replacement bodies are used only for wallet history / receipt artifacts.
#[allow(clippy::too_many_arguments)]
pub fn install_reorg_snapshot_and_artifacts(
    wallet: &SharedWallet,
    expected_active_index: u32,
    expected_next_index: u32,
    owner: [u8; 32],
    snapshot: VerifiedOwnerSnapshot,
    reserved_input_slots: &std::collections::HashSet<u32>,
    reserved_output_slots: &std::collections::HashSet<u32>,
    reclaimed_tx_hashes: &[noid_poseidon2b::primitives::TxBodyHash],
    replacement_blocks: &[&noid_chain::block::Block],
) -> Result<(), String> {
    let mut guard = wallet
        .lock()
        .map_err(|_| "wallet state lock is poisoned".to_string())?;

    let Some(wallet) = guard.as_mut() else {
        return Ok(());
    };

    wallet.commit_verified_activation(
        expected_active_index,
        expected_next_index,
        expected_active_index,
        owner,
        snapshot,
        reserved_input_slots,
        reserved_output_slots,
    )?;

    let reclaimed: std::collections::HashSet<[u8; 32]> =
        reclaimed_tx_hashes.iter().map(|hash| hash.0).collect();

    // Receipts bind to the orphaned header and tx position.
    // They cannot survive a reorg unchanged.
    for tx_hash in &reclaimed {
        wallet.receipts.remove(tx_hash);
    }

    let replacement: std::collections::HashSet<[u8; 32]> = replacement_blocks
        .iter()
        .flat_map(|block| {
            noid_chain::try_compute_logical_txids(&block.transactions)
                .expect("committed replacement block has canonical logical tx stream")
        })
        .map(|txid| txid.0)
        .collect();

    wallet.history.retain_mut(|entry| {
        if !reclaimed.contains(&entry.tx_hash) {
            return true;
        }

        // Locally mined blocks remain historical records even after
        // becoming orphaned.
        if entry.is_coinbase {
            return true;
        }

        if replacement.contains(&entry.tx_hash) && entry.direction == state::TxDirection::Sent {
            // Preserve source-account metadata so canonical replacement
            // confirmation can generate a fresh receipt.
            entry.height = 0;
            return true;
        }

        false
    });

    wallet.ensure_generated_address_index();

    let active_address = wallet.active_address();
    let active_index = wallet.active_index;

    for block in replacement_blocks {
        scanner::update_wallet_artifacts_from_block(
            &mut wallet.history,
            &mut wallet.receipts,
            active_address,
            active_index,
            block,
        );

        scanner::update_walletwide_received_history_from_block(
            &mut wallet.history,
            &wallet.generated_address_index,
            block,
        )?;

        let confirmed_block_hash = noid_chain::block_id(&block.header);

        for transaction in &block.transactions {
            let _ = wallet.confirm_pending_tx(
                &transaction.txid().0,
                block.header.height,
                confirmed_block_hash,
            );

            let output_slots: Vec<u32> = transaction
                .body
                .live_outputs()
                .map(|(_, output)| output.slot_index)
                .collect();

            wallet.remove_pending_outputs(&output_slots);
        }
    }

    wallet.mark_history_dirty();
    wallet.mark_receipts_dirty();

    wallet.save_history()?;

    // Persist even an empty map. Otherwise deleting the last orphan-bound
    // receipt only in RAM would resurrect it after restart.
    wallet.save_receipts()?;

    Ok(())
}

/// Fail closed when a post-reorg verified owner snapshot cannot be installed.
///
/// A later verified wallet reload reconstructs the active cache from MDBX.
pub fn invalidate_active_cache(wallet: &SharedWallet) {
    let Ok(mut guard) = wallet.lock() else {
        return;
    };

    if let Some(wallet) = guard.as_mut() {
        wallet.utxos.clear();
        wallet.pending_input_slots.clear();
        wallet.active_snapshot = None;
    }
}
