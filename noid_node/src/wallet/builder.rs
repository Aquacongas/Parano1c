// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transaction builder for the Paranoid wallet.
//!
//! This is the only place that assembles a complete [`TxIntent`] from UTXOs
//! and spending secrets. The two-phase API separates lock-holding work
//! (coin selection + secret extraction via [`extract_build_data`]) from the
//! CPU-heavy proving work (via [`build_and_prove_tx`]), so the wallet mutex
//! is held for as short a time as possible.
//!
//! # Auth-tag ordering
//!
//! Auth tags are computed AFTER the body hash, because they are NOT part of
//! the body hash input. The correct order is:
//!
//! 1. Build inputs with `AuthTag([0; 32])` placeholders.
//! 2. `tx_body_hash = hash_tx_body(epoch_anchor, fee, inputs, outputs, false)`
//! 3. For each live input: `auth_tag = hash_auth_tag(spend_secret, tx_body_hash)`
//! 4. Fill auth tags in place.
//! 5. `prove_tx(&body, spend_secrets)` → `WalletProofBundle`

use noid_poseidon2b::primitives::{hash_auth_tag, Address, AuthTag, SpendSecret};
use noid_tx::{
    body_hash::hash_tx_body,
    claims::compute_claims_commitment,
    intent::TxIntent,
    types::{TxBody, TxInput, TxOutput},
    MAX_INPUTS,
};

use crate::wallet::prover::prove_tx;
use crate::wallet::state::{WalletState, WalletUtxo};

// ---------------------------------------------------------------------------
// TxBuildData
// ---------------------------------------------------------------------------

/// All data extracted from [`WalletState`] while holding the wallet lock.
///
/// Passed to [`build_and_prove_tx`], which runs **without** the wallet lock
/// so the CPU-heavy proving step does not block other wallet operations.
pub struct TxBuildData {
    /// Owned copies of the UTXOs selected for spending.
    pub selected_utxos: Vec<WalletUtxo>,
    /// Spending secret for each selected UTXO (index-aligned with `selected_utxos`).
    /// Zeroized on drop via [`SpendSecret`]'s `ZeroizeOnDrop` impl.
    pub spend_secrets: Vec<SpendSecret>,
    /// Change address (wallet primary address). Excess funds return here.
    pub change_address: Address,
    /// Epoch anchor bytes from the chain tip (anti-replay / natural TTL).
    pub epoch_anchor: [u8; 32],
    /// Free-slot hints for outputs: index `0` = payment output slot,
    /// index `1` = change output slot (present only when change > 0).
    pub output_slot_hints: Vec<u32>,
    /// `log2(state_size)` — passed to `prove_tx` to select the correct AIR shape.
    pub log_slots: u32,
}

// ---------------------------------------------------------------------------
// BuildError
// ---------------------------------------------------------------------------

/// Errors that can occur during transaction construction.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("insufficient funds: need {need} μNOID, have {have} μNOID")]
    InsufficientFunds { need: u64, have: u64 },

    #[error("too many inputs needed (selected {selected}, max {max})")]
    TooManyInputs { selected: usize, max: usize },

    #[error("not enough output slot hints (need {need}, got {got})")]
    NotEnoughSlots { need: usize, got: usize },

    #[error("proving failed: {0}")]
    ProveFailed(String),
}

// ---------------------------------------------------------------------------
// extract_build_data
// ---------------------------------------------------------------------------

/// Extract build data from [`WalletState`] while holding the wallet lock.
///
/// Performs coin selection (largest-first) and derives spending secrets for
/// the selected UTXOs. The caller must hold the wallet mutex for the entire
/// duration of this call, then release it before invoking [`build_and_prove_tx`].
///
/// # Errors
///
/// - [`BuildError::InsufficientFunds`] — confirmed balance is below
///   `amount_micronoid + fee_micronoid`.
/// - [`BuildError::TooManyInputs`] — coin selection required more than
///   [`MAX_INPUTS`] UTXOs to cover the target amount.
/// - [`BuildError::NotEnoughSlots`] — `slot_hints` did not supply enough
///   free-slot indices for all outputs (1 for payment, +1 if change > 0).
pub fn extract_build_data(
    wallet: &WalletState,
    amount_micronoid: u64,
    fee_micronoid: u64,
    epoch_anchor: [u8; 32],
    slot_hints: Vec<u32>,
    log_slots: u32,
    pending_output_slots: &std::collections::HashSet<u32>,
) -> Result<TxBuildData, BuildError> {
    let total_needed = amount_micronoid.saturating_add(fee_micronoid);

    // Coin selection — largest-first, returns (selected, change_amount).
    let (selected_refs, change_amount) = wallet
        .select_utxos(amount_micronoid, fee_micronoid)
        .ok_or(BuildError::InsufficientFunds {
            need: total_needed,
            have: wallet.balance(),
        })?;

    // Reject if selection would exceed the circuit's fixed input count.
    if selected_refs.len() > MAX_INPUTS {
        return Err(BuildError::TooManyInputs {
            selected: selected_refs.len(),
            max: MAX_INPUTS,
        });
    }

    // Filter out slots already claimed by in-flight (pending) txs to prevent
    // SlotConflict when wallet_send is retried or called concurrently.
    let slot_hints: Vec<u32> = slot_hints
        .into_iter()
        .filter(|s| !pending_output_slots.contains(s))
        .collect();

    // 1 slot for the payment output, +1 if there is change to return.
    let needed_slots: usize = if change_amount > 0 { 2 } else { 1 };
    if slot_hints.len() < needed_slots {
        return Err(BuildError::NotEnoughSlots {
            need: needed_slots,
            got: slot_hints.len(),
        });
    }

    // Clone UTXOs and derive secrets while holding the wallet lock.
    let selected_utxos: Vec<WalletUtxo> = selected_refs.into_iter().map(|u| u.clone()).collect();

    let spend_secrets: Vec<SpendSecret> = selected_utxos
        .iter()
        .map(|u| wallet.spend_secret_for(u.key_index))
        .collect();

    Ok(TxBuildData {
        selected_utxos,
        spend_secrets,
        change_address: wallet.primary_address(),
        epoch_anchor,
        output_slot_hints: slot_hints,
        log_slots,
    })
}

// ---------------------------------------------------------------------------
// extract_consolidate_data
// ---------------------------------------------------------------------------

/// Build `TxBuildData` for a consolidation transaction.
///
/// Consolidation selects the **smallest** UTXOs (up to [`MAX_INPUTS`] = 4)
/// and sends their total value minus fee back to the wallet's own address.
/// This reduces the UTXO count by up to `MAX_INPUTS - 1` per call.
///
/// Unlike `extract_build_data` (which uses largest-first greedy selection to
/// cover a target amount), this function explicitly selects the smallest UTXOs
/// to maximise UTXO reduction.
///
/// Returns `(TxBuildData, consolidation_amount_micronoid)` on success, where
/// `consolidation_amount_micronoid` is what the caller should pass as
/// `amount_micronoid` to `build_and_prove_tx`.
///
/// # Errors
///
/// - `InsufficientFunds`: total of smallest UTXOs ≤ fee.
/// - `NotEnoughSlots`: fewer than 1 empty slot hint available.
pub fn extract_consolidate_data(
    wallet: &WalletState,
    fee_micronoid: u64,
    epoch_anchor: [u8; 32],
    slot_hints: Vec<u32>,
    log_slots: u32,
    pending_output_slots: &std::collections::HashSet<u32>,
    pending_input_slots: &std::collections::HashSet<u32>,
) -> Result<(TxBuildData, u64), BuildError> {
    // Sort all UTXOs smallest-first, skipping any whose slot is already being
    // spent by a pending (unconfirmed) TX. This prevents double-spend
    // SlotConflict errors when multiple consolidation rounds are submitted
    // before the first round is confirmed in a block.
    let mut all_utxos: Vec<&WalletUtxo> = wallet
        .utxos
        .values()
        .filter(|u| !pending_input_slots.contains(&u.slot_index))
        .collect();
    all_utxos.sort_by_key(|u| u.value);
    let selected: Vec<WalletUtxo> = all_utxos.into_iter().take(MAX_INPUTS).cloned().collect();

    if selected.is_empty() {
        return Err(BuildError::InsufficientFunds {
            need: fee_micronoid,
            have: 0,
        });
    }

    let total: u64 = selected.iter().map(|u| u.value).sum();
    if total <= fee_micronoid {
        return Err(BuildError::InsufficientFunds {
            need: fee_micronoid.saturating_add(1),
            have: total,
        });
    }
    let consolidation_amount = total - fee_micronoid;

    // Consolidation has no change: one output (to self).
    let slot_hints: Vec<u32> = slot_hints
        .into_iter()
        .filter(|s| !pending_output_slots.contains(s))
        .collect();
    if slot_hints.is_empty() {
        return Err(BuildError::NotEnoughSlots { need: 1, got: 0 });
    }

    let spend_secrets: Vec<SpendSecret> = selected
        .iter()
        .map(|u| wallet.spend_secret_for(u.key_index))
        .collect();

    Ok((
        TxBuildData {
            selected_utxos: selected,
            spend_secrets,
            change_address: wallet.primary_address(),
            epoch_anchor,
            output_slot_hints: slot_hints,
            log_slots,
        },
        consolidation_amount,
    ))
}

// ---------------------------------------------------------------------------
// build_and_prove_tx
// ---------------------------------------------------------------------------

/// Build, prove, and serialize a send transaction. Called **without** the
/// wallet lock.
///
/// This function is CPU-heavy (~0.3–3 s depending on hardware) due to the ZK
/// proving step; keep the wallet mutex released for the full duration.
///
/// # Construction order
///
/// 1. Build outputs: payment output at `slot_hints[0]`; change output at
///    `slot_hints[1]` if `change_amount > 0`.
/// 2. Build live inputs with `AuthTag([0; 32])` placeholders.
/// 3. Pad inputs to [`MAX_INPUTS`] with `TxInput::dummy()` (`valid = false`).
/// 4. `tx_body_hash = hash_tx_body(epoch_anchor, fee, inputs, outputs, false)`.
///    Auth tags are intentionally excluded from the body hash.
/// 5. For each live input: `auth_tag = hash_auth_tag(spend_secret, tx_body_hash)`.
/// 6. Fill real auth tags into the live input slots.
/// 7. `prove_tx(&body, spend_secrets)` → `WalletProofBundle`
///    (secrets are consumed and zeroized inside).
/// 8. `claims_commitment = compute_claims_commitment(inputs, outputs)`.
/// 9. Assemble and wire-encode the [`TxIntent`].
///
/// # Returns
///
/// `(tx_body_hash_bytes, serialized_TxIntent_bytes)` on success.
///
/// # Errors
///
/// - [`BuildError::ProveFailed`] — the ZK prover returned an error.
pub fn build_and_prove_tx(
    to_address: [u8; 32],
    amount_micronoid: u64,
    fee_micronoid: u64,
    data: TxBuildData,
) -> Result<([u8; 32], Vec<u8>), BuildError> {
    // -----------------------------------------------------------------------
    // Build outputs.
    // -----------------------------------------------------------------------
    let total_selected: u64 = data.selected_utxos.iter().map(|u| u.value).sum();
    // Subtraction is safe: extract_build_data already validated that
    // total_selected >= amount_micronoid + fee_micronoid.
    let change_amount = total_selected - amount_micronoid - fee_micronoid;

    let mut outputs: Vec<TxOutput> = Vec::with_capacity(2);
    outputs.push(TxOutput {
        slot_index: data.output_slot_hints[0],
        value: amount_micronoid,
        owner: Address(to_address),
        valid: true,
    });
    if change_amount > 0 {
        outputs.push(TxOutput {
            slot_index: data.output_slot_hints[1],
            value: change_amount,
            owner: data.change_address,
            valid: true,
        });
    }

    // -----------------------------------------------------------------------
    // Steps 2–3: Build live inputs with dummy auth tags; pad to MAX_INPUTS.
    // -----------------------------------------------------------------------
    let n_live = data.selected_utxos.len();

    let mut inputs: Vec<TxInput> = data
        .selected_utxos
        .iter()
        .zip(data.spend_secrets.iter())
        .map(|(utxo, secret)| TxInput {
            slot_index: utxo.slot_index,
            value: utxo.value,
            owner: utxo.address,
            // Copy secret bytes into the input witness slot.
            // The original in data.spend_secrets is still live for prove_tx.
            spend_secret: SpendSecret(secret.0),
            auth_tag: AuthTag([0u8; 32]), // placeholder — filled after body hash
            valid: true,
        })
        .collect();

    while inputs.len() < MAX_INPUTS {
        inputs.push(TxInput::dummy());
    }

    // -----------------------------------------------------------------------
    // Compute the body hash. Auth tags are NOT inputs to this hash.
    // -----------------------------------------------------------------------
    let tx_body_hash = hash_tx_body(
        &data.epoch_anchor,
        fee_micronoid as u128,
        &inputs,
        &outputs,
        false,
    );

    // -----------------------------------------------------------------------
    // Steps 5–6: Derive real auth tags and fill them into the live input slots.
    // -----------------------------------------------------------------------
    for (i, secret) in data.spend_secrets.iter().enumerate().take(n_live) {
        inputs[i].auth_tag = hash_auth_tag(secret, &tx_body_hash);
    }

    // -----------------------------------------------------------------------
    // Assemble TxBody and run the ZK prover.
    //
    // spend_secrets is consumed here; SpendSecret's ZeroizeOnDrop impl
    // ensures the raw key material is cleared from memory when prove_tx returns.
    // -----------------------------------------------------------------------
    let body = TxBody {
        epoch_anchor: data.epoch_anchor,
        fee: fee_micronoid as u128,
        inputs,
        outputs,
        is_coinbase: false,
    };

    let bundle = prove_tx(&body, data.spend_secrets, data.log_slots)
        .map_err(|e| BuildError::ProveFailed(e.to_string()))?;

    let logic_proof_bytes = bundle.to_bytes();

    // -----------------------------------------------------------------------
    // Steps 8–9: Claims commitment, claimed slots, assemble TxIntent.
    // -----------------------------------------------------------------------
    let claims_commitment = compute_claims_commitment(&body.inputs, &body.outputs);
    let claimed_slots = TxIntent::claimed_slots_from_body(&body);

    let intent = TxIntent {
        tx_body: body,
        tx_body_hash,
        claims_commitment,
        claimed_slots,
        logic_proof_bytes,
    };

    Ok((tx_body_hash.0, intent.to_bytes()))
}
