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
use noid_poseidon2b::primitives::{Address, SpendSecret};
use noid_tx::{
    body_hash::hash_tx_body_for_shape,
    intent::TxIntent,
    types::{TxBody, TxInput, TxOutput, TxShape},
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
    /// Transaction proof/body shape selected by coin selection.
    pub shape: TxShape,
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
///   the largest currently admitted transaction proof shape to cover the target amount.
/// - [`BuildError::NotEnoughSlots`] — `slot_hints` did not supply enough
///   free-slot indices for all outputs (1 for payment, +1 if change > 0).
pub fn extract_build_data(
    wallet: &WalletState,
    amount_micronoid: u64,
    fee_micronoid: u64,
    epoch_anchor: [u8; 32],
    slot_hints: Vec<u32>,
    _log_slots: u32,
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

    // Select the smallest proof shape that can carry the selected inputs.
    let shape = if selected_refs.len() <= TxShape::Standard4x8.max_inputs() {
        TxShape::Standard4x8
    } else {
        TxShape::Sweep25x2
    };
    if selected_refs.len() > shape.max_inputs() {
        return Err(BuildError::TooManyInputs {
            selected: selected_refs.len(),
            max: shape.max_inputs(),
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
    let selected_utxos: Vec<WalletUtxo> = selected_refs.into_iter().cloned().collect();

    let spend_secrets: Vec<SpendSecret> = selected_utxos
        .iter()
        .map(|u| wallet.spend_secret_for(u.key_index))
        .collect();

    Ok(TxBuildData {
        selected_utxos,
        spend_secrets,
        change_address: wallet.active_address(),
        epoch_anchor,
        output_slot_hints: slot_hints,
        shape,
    })
}

// ---------------------------------------------------------------------------
// extract_consolidate_data
// ---------------------------------------------------------------------------

/// Build `TxBuildData` for a consolidation transaction.
///
/// Consolidation selects the **smallest** UTXOs, capped by the largest current
/// transaction proof shape, and sends their total value minus fee back to the
/// wallet's own address. It uses `TxShape::Standard4x8` for 1..4 selected inputs
/// and `TxShape::Sweep25x2` for 5..25 selected inputs.
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
/// - `InsufficientFunds`: fewer than 2 available UTXOs, or total of selected
///   UTXOs ≤ fee.
/// - `NotEnoughSlots`: fewer than 1 empty slot hint available.
pub fn extract_consolidate_data(
    wallet: &WalletState,
    fee_micronoid: u64,
    epoch_anchor: [u8; 32],
    slot_hints: Vec<u32>,
    _log_slots: u32,
    pending_output_slots: &std::collections::HashSet<u32>,
    pending_input_slots: &std::collections::HashSet<u32>,
) -> Result<(TxBuildData, u64), BuildError> {
    // Sort the ACTIVE address's UTXOs smallest-first (one owner per
    // transaction — the consensus rule; other addresses consolidate only
    // after the user switches to them), skipping any whose slot is
    // already being spent by a pending (unconfirmed) TX. This prevents
    // double-spend SlotConflict errors when multiple consolidation rounds
    // are submitted before the first round is confirmed in a block.
    let mut all_utxos: Vec<&WalletUtxo> = wallet
        .utxos
        .values()
        .filter(|u| u.key_index == wallet.active_index)
        .filter(|u| !pending_input_slots.contains(&u.slot_index))
        .collect();
    all_utxos.sort_by_key(|u| u.value);
    let selected: Vec<WalletUtxo> = all_utxos
        .into_iter()
        .take(TxShape::Sweep25x2.max_inputs())
        .cloned()
        .collect();

    if selected.len() < 2 {
        return Err(BuildError::InsufficientFunds {
            need: fee_micronoid,
            have: selected.iter().map(|u| u.value).sum(),
        });
    }

    let shape = if selected.len() <= TxShape::Standard4x8.max_inputs() {
        TxShape::Standard4x8
    } else {
        TxShape::Sweep25x2
    };

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
            change_address: wallet.active_address(),
            epoch_anchor,
            output_slot_hints: slot_hints,
            shape,
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
/// This function is CPU-heavy (~0.3–3 s depending on hardware) due to the
/// wallet authorization generation step; keep the wallet mutex released for the
/// full duration.
///
/// # Construction order
///
/// 1. Build outputs: payment output at `slot_hints[0]`; change output at
///    `slot_hints[1]` if `change_amount > 0`.
/// 2. Build live inputs.
/// 3. Pad inputs to the selected shape with `TxInput::dummy()` (`valid = false`).
/// 4. `tx_body_hash = hash_tx_body_for_shape(shape, epoch_anchor, fee, inputs, outputs, false)`.
/// 5. `prove_tx(&body, spend_secrets)` → `WalletAuthorizationBundle`
///    (secrets are consumed and zeroized inside).
/// 6. Assemble and wire-encode the [`TxIntent`]; validators derive claims from
///    the hash-bound body.
///
/// # Returns
///
/// `(tx_body_hash_bytes, serialized_TxIntent_bytes)` on success.
///
/// # Errors
///
/// - [`BuildError::ProveFailed`] — wallet authorization generation returned an error.
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
    // Steps 2–3: Build live inputs; pad to selected shape.
    // -----------------------------------------------------------------------
    let mut inputs: Vec<TxInput> = data
        .selected_utxos
        .iter()
        .zip(data.spend_secrets.iter())
        .map(|(utxo, secret)| TxInput {
            slot_index: utxo.slot_index,
            value: utxo.value,
            creation_id: utxo.creation_id,
            owner: utxo.address,
            // Copy secret bytes into the input witness slot.
            // The original in data.spend_secrets is still live for prove_tx.
            spend_secret: SpendSecret(secret.0),
            valid: true,
        })
        .collect();

    while inputs.len() < data.shape.max_inputs() {
        inputs.push(TxInput::dummy());
    }

    // -----------------------------------------------------------------------
    // Compute the body hash.
    // -----------------------------------------------------------------------
    let tx_body_hash = hash_tx_body_for_shape(
        data.shape,
        &data.epoch_anchor,
        fee_micronoid as u128,
        &inputs,
        &outputs,
        false,
    );

    // -----------------------------------------------------------------------
    // Assemble TxBody and run wallet authorization generation.
    //
    // spend_secrets is consumed here; SpendSecret's ZeroizeOnDrop impl
    // ensures the raw key material is cleared from memory when prove_tx returns.
    // -----------------------------------------------------------------------
    let body = TxBody {
        shape: data.shape,
        epoch_anchor: data.epoch_anchor,
        fee: fee_micronoid as u128,
        inputs,
        outputs,
        is_coinbase: false,
    };

    let bundle =
        prove_tx(&body, data.spend_secrets).map_err(|e| BuildError::ProveFailed(e.to_string()))?;

    let authorization_bytes = bundle
        .to_bytes()
        .map_err(|e| BuildError::ProveFailed(e.to_string()))?;

    // -----------------------------------------------------------------------
    // Assemble the minimal TxIntent. A second claims/slot copy would be
    // redundant and malleable; validators derive it from `body`.
    // -----------------------------------------------------------------------
    let intent = TxIntent {
        tx_body: body,
        tx_body_hash,
        authorization_bytes,
    };

    Ok((tx_body_hash.0, intent.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn wallet_with_utxos(n: u32, value: u64) -> (TempDir, WalletState) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(path).unwrap();
        for i in 0..n {
            wallet.utxos.insert(
                i,
                WalletUtxo {
                    slot_index: i,
                    value,
                    creation_id: u64::from(i) + 1,
                    // One owner per tx: the fixture's UTXOs all live on the
                    // ACTIVE (index-0) address.
                    address: wallet.address_at(0),
                    key_index: 0,
                    confirmed_height: 1,
                },
            );
        }
        (dir, wallet)
    }

    fn extract_for(wallet: &WalletState, amount: u64, fee: u64) -> Result<TxBuildData, BuildError> {
        extract_build_data(
            wallet,
            amount,
            fee,
            [0x11; 32],
            vec![50_000, 50_001],
            24,
            &std::collections::HashSet::new(),
        )
    }

    #[test]
    fn extract_build_data_uses_standard_for_four_inputs() {
        let (_dir, wallet) = wallet_with_utxos(4, 1_000);
        let data = extract_for(&wallet, 3_500, 500).unwrap();
        assert_eq!(data.selected_utxos.len(), 4);
        assert_eq!(data.shape, TxShape::Standard4x8);
    }

    #[test]
    fn extract_build_data_uses_sweep_for_five_inputs() {
        let (_dir, wallet) = wallet_with_utxos(5, 1_000);
        let data = extract_for(&wallet, 4_500, 500).unwrap();
        assert_eq!(data.selected_utxos.len(), 5);
        assert_eq!(data.shape, TxShape::Sweep25x2);
    }

    #[test]
    fn extract_build_data_rejects_more_than_sweep_capacity() {
        let (_dir, wallet) = wallet_with_utxos(26, 1_000);
        let err = match extract_for(&wallet, 26_000, 0) {
            Ok(_) => panic!("expected too many inputs error"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            BuildError::TooManyInputs {
                selected: 26,
                max: 25
            }
        ));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
    fn build_and_prove_tx_emits_sweep_intent_for_five_inputs() {
        let (_dir, wallet) = wallet_with_utxos(5, 20_000);
        let amount = 80_000;
        let fee = 18_500;
        let data = extract_for(&wallet, amount, fee).unwrap();
        assert_eq!(data.shape, TxShape::Sweep25x2);

        let (tx_hash, intent_bytes) =
            build_and_prove_tx([0xA7; 32], amount, fee, data).expect("prove sweep wallet tx");
        let intent = TxIntent::from_bytes(&intent_bytes).expect("decode intent");
        assert_eq!(intent.tx_body.shape, TxShape::Sweep25x2);
        assert_eq!(intent.tx_body.inputs.iter().filter(|i| i.valid).count(), 5);
        let mut creation_ids: Vec<u64> = intent
            .tx_body
            .inputs
            .iter()
            .filter(|input| input.valid)
            .map(|input| input.creation_id)
            .collect();
        creation_ids.sort_unstable();
        assert_eq!(creation_ids, vec![1, 2, 3, 4, 5]);
        assert_eq!(intent.tx_body_hash.0, tx_hash);

        let bundle = noid_gkr::WalletAuthorizationBundle::from_bytes(&intent.authorization_bytes)
            .expect("decode wallet authorization bundle");
        noid_gkr::verify_wallet_authorization(&intent.tx_body, &bundle)
            .expect("verify sweep authorization bundle");
    }
}
