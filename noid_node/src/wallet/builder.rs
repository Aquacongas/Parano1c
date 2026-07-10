// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transaction builder for the Paranoid wallet.
//!
//! This is the only place that assembles a complete [`TxIntent`] from UTXOs
//! and one active-owner proving capability. The two-phase API separates
//! lock-holding work (coin selection + witness extraction via
//! [`extract_build_data`]) from the
//! CPU-heavy proving work (via [`build_and_prove_tx`]), so the wallet mutex
//! is held for as short a time as possible.
//!
use noid_gkr::OwnerAuthWitness;
use noid_poseidon2b::primitives::{derive_address, Address};
use noid_tx::{
    intent::TxIntent,
    output_bitmap_bit,
    types::{TxBody, TxInput, TxOutput},
    TX_INPUTS, TX_OUTPUTS,
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
    /// One proving capability for the active owner shared by every selected
    /// UTXO. It is non-cloneable/non-serializable and zeroizes its secret on
    /// drop; public transaction records carry only zero placeholders.
    pub owner_auth_witness: OwnerAuthWitness,
    /// Change address (the captured active address). Excess funds return here.
    pub change_address: Address,
    /// Exact transaction-epoch anchor accepted in the next child block.
    pub epoch_anchor: [u8; 32],
    /// Free-slot hints for outputs: index `0` = payment output slot,
    /// index `1` = change output slot (present only when change > 0).
    pub output_slot_hints: Vec<u32>,
}

// ---------------------------------------------------------------------------
// BuildError
// ---------------------------------------------------------------------------

/// Errors that can occur during transaction construction.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("insufficient funds: need {need} μNOID, have {have} μNOID")]
    InsufficientFunds { need: u64, have: u64 },

    #[error("payment needs more than {max} active UTXOs (selected at least {selected}); consolidation required")]
    TooManyInputs { selected: usize, max: usize },

    #[error("not enough output slot hints (need {need}, got {got})")]
    NotEnoughSlots { need: usize, got: usize },

    #[error("proving failed: {0}")]
    ProveFailed(String),

    #[error("selected UTXO set is not owned exclusively by the active address")]
    ActiveOwnerMismatch,

    #[error("wallet amount arithmetic overflow")]
    AmountOverflow,

    #[error("target consolidation requires 1..={max} unique inputs, got {got}")]
    InvalidExactInputCount { got: usize, max: usize },

    #[error("target consolidation repeats input slot {slot_index}")]
    DuplicateExactInput { slot_index: u32 },

    #[error("target consolidation input slot {slot_index} is no longer live")]
    ExactInputMissing { slot_index: u32 },

    #[error("target consolidation input slot {slot_index} is pending another transaction")]
    ExactInputPending { slot_index: u32 },

    #[error("target consolidation input slot {slot_index} is not confirmed")]
    ExactInputUnconfirmed { slot_index: u32 },

    #[error("target consolidation outputs must be non-zero")]
    ZeroExactOutput,

    #[error(
        "target consolidation plan diverged: selected inputs total {input_total_micronoid} μNOID, outputs plus fee total {output_and_fee_micronoid} μNOID"
    )]
    ExactPlanDiverged {
        input_total_micronoid: u64,
        output_and_fee_micronoid: u64,
    },
}

fn active_owner_witness(
    wallet: &WalletState,
    selected: &[WalletUtxo],
) -> Result<OwnerAuthWitness, BuildError> {
    let active_index = wallet.active_index;
    let active_address = wallet.active_address();
    if selected
        .iter()
        .any(|utxo| utxo.key_index != active_index || utxo.address != active_address)
    {
        return Err(BuildError::ActiveOwnerMismatch);
    }

    let spend_secret = wallet.spend_secret_for(active_index);
    if derive_address(&spend_secret) != active_address {
        return Err(BuildError::ActiveOwnerMismatch);
    }
    Ok(OwnerAuthWitness::new(spend_secret))
}

// ---------------------------------------------------------------------------
// extract_build_data
// ---------------------------------------------------------------------------

/// Extract build data from [`WalletState`] while holding the wallet lock.
///
/// Performs coin selection (largest-first) and derives one owner witness for
/// the selected UTXOs. The caller must hold the wallet mutex for the entire
/// duration of this call, then release it before invoking [`build_and_prove_tx`].
///
/// # Errors
///
/// - [`BuildError::InsufficientFunds`] — confirmed balance is below
///   `amount_micronoid + fee_micronoid`.
/// - [`BuildError::TooManyInputs`] — the payment cannot be covered by one
///   canonical eight-input transaction.
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
    let total_needed = amount_micronoid
        .checked_add(fee_micronoid)
        .ok_or(BuildError::AmountOverflow)?;

    // Coin selection — largest-first, returns (selected, change_amount).
    let (selected_refs, change_amount) = match wallet.select_utxos(amount_micronoid, fee_micronoid)
    {
        Some(selection) => selection,
        None => {
            let spendable = wallet
                .utxos
                .values()
                .filter(|utxo| utxo.key_index == wallet.active_index)
                .filter(|utxo| !wallet.pending_input_slots.contains(&utxo.slot_index))
                .map(|utxo| utxo.value)
                .try_fold(0u64, u64::checked_add)
                .ok_or(BuildError::AmountOverflow)?;
            if spendable >= total_needed {
                return Err(BuildError::TooManyInputs {
                    selected: TX_INPUTS + 1,
                    max: TX_INPUTS,
                });
            }
            return Err(BuildError::InsufficientFunds {
                need: total_needed,
                have: spendable,
            });
        }
    };

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

    // Clone UTXOs and derive the active owner's one proving capability while
    // holding the wallet lock.
    let selected_utxos: Vec<WalletUtxo> = selected_refs.into_iter().cloned().collect();
    let owner_auth_witness = active_owner_witness(wallet, &selected_utxos)?;

    Ok(TxBuildData {
        selected_utxos,
        owner_auth_witness,
        change_address: wallet.active_address(),
        epoch_anchor,
        output_slot_hints: slot_hints,
    })
}

// ---------------------------------------------------------------------------
// extract_exact_active_inputs_data
// ---------------------------------------------------------------------------

/// Revalidate and capture one transaction from a targeted-consolidation plan.
///
/// Unlike ordinary payment selection and miner maintenance, this function
/// never chooses a substitute coin. `input_slots` is the plan/build contract:
/// if any exact slot changed ownership, became pending, disappeared, or no
/// longer conserves the planned output values and fee, construction fails.
#[allow(clippy::too_many_arguments)]
pub fn extract_exact_active_inputs_data(
    wallet: &WalletState,
    input_slots: &[u32],
    output_amount_micronoid: u64,
    change_micronoid: Option<u64>,
    fee_micronoid: u64,
    epoch_anchor: [u8; 32],
    slot_hints: Vec<u32>,
    _log_slots: u32,
    pending_output_slots: &std::collections::HashSet<u32>,
) -> Result<TxBuildData, BuildError> {
    if input_slots.is_empty() || input_slots.len() > TX_INPUTS {
        return Err(BuildError::InvalidExactInputCount {
            got: input_slots.len(),
            max: TX_INPUTS,
        });
    }
    if output_amount_micronoid == 0 || change_micronoid == Some(0) {
        return Err(BuildError::ZeroExactOutput);
    }

    let mut seen_inputs = std::collections::HashSet::with_capacity(input_slots.len());
    let active_index = wallet.active_index;
    let active_address = wallet.active_address();
    let mut selected = Vec::with_capacity(input_slots.len());
    for &slot_index in input_slots {
        if !seen_inputs.insert(slot_index) {
            return Err(BuildError::DuplicateExactInput { slot_index });
        }
        if wallet.pending_input_slots.contains(&slot_index) {
            return Err(BuildError::ExactInputPending { slot_index });
        }
        let utxo = wallet
            .utxos
            .get(&slot_index)
            .ok_or(BuildError::ExactInputMissing { slot_index })?;
        if utxo.confirmed_height == 0 {
            return Err(BuildError::ExactInputUnconfirmed { slot_index });
        }
        if utxo.key_index != active_index || utxo.address != active_address {
            return Err(BuildError::ActiveOwnerMismatch);
        }
        selected.push(utxo.clone());
    }

    let input_total_micronoid = selected
        .iter()
        .try_fold(0u64, |sum, utxo| sum.checked_add(utxo.value))
        .ok_or(BuildError::AmountOverflow)?;
    let output_and_fee_micronoid = output_amount_micronoid
        .checked_add(change_micronoid.unwrap_or(0))
        .and_then(|sum| sum.checked_add(fee_micronoid))
        .ok_or(BuildError::AmountOverflow)?;
    if input_total_micronoid != output_and_fee_micronoid {
        return Err(BuildError::ExactPlanDiverged {
            input_total_micronoid,
            output_and_fee_micronoid,
        });
    }

    let needed_slots = 1 + usize::from(change_micronoid.is_some());
    let mut seen_output_slots = std::collections::HashSet::new();
    let slot_hints: Vec<u32> = slot_hints
        .into_iter()
        .filter(|slot| !pending_output_slots.contains(slot))
        .filter(|slot| seen_output_slots.insert(*slot))
        .collect();
    if slot_hints.len() < needed_slots {
        return Err(BuildError::NotEnoughSlots {
            need: needed_slots,
            got: slot_hints.len(),
        });
    }

    let owner_auth_witness = active_owner_witness(wallet, &selected)?;
    Ok(TxBuildData {
        selected_utxos: selected,
        owner_auth_witness,
        change_address: active_address,
        epoch_anchor,
        output_slot_hints: slot_hints,
    })
}

// ---------------------------------------------------------------------------
// extract_consolidate_data
// ---------------------------------------------------------------------------

/// Build `TxBuildData` for a consolidation transaction.
///
/// Consolidation selects the eight smallest available active-owner UTXOs and
/// sends their total value minus fee back to the same active address. It is an
/// ordinary canonical transaction, not a distinct transaction class.
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
    let selected: Vec<WalletUtxo> = all_utxos.into_iter().take(TX_INPUTS).cloned().collect();

    if selected.len() < 2 {
        let have = selected
            .iter()
            .try_fold(0u64, |sum, utxo| sum.checked_add(utxo.value))
            .ok_or(BuildError::AmountOverflow)?;
        return Err(BuildError::InsufficientFunds {
            need: fee_micronoid,
            have,
        });
    }

    let total = selected
        .iter()
        .try_fold(0u64, |sum, utxo| sum.checked_add(utxo.value))
        .ok_or(BuildError::AmountOverflow)?;
    if total <= fee_micronoid {
        return Err(BuildError::InsufficientFunds {
            need: fee_micronoid
                .checked_add(1)
                .ok_or(BuildError::AmountOverflow)?,
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

    let owner_auth_witness = active_owner_witness(wallet, &selected)?;

    Ok((
        TxBuildData {
            selected_utxos: selected,
            owner_auth_witness,
            change_address: wallet.active_address(),
            epoch_anchor,
            output_slot_hints: slot_hints,
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
/// 2. Build the fixed input/output arrays and their sole validity bitmap.
/// 3. Derive the txid from the canonical body.
/// 5. `prove_tx(&body, owner_auth_witness)` → `WalletAuthorizationBundle`;
///    the one secret is consumed and zeroized inside.
/// 6. Assemble and wire-encode the [`TxIntent`]; validators derive claims from
///    the hash-bound body.
///
/// # Returns
///
/// `(txid_bytes, serialized_TxIntent_bytes)` on success.
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
    let total_selected = data
        .selected_utxos
        .iter()
        .try_fold(0u64, |sum, utxo| sum.checked_add(utxo.value))
        .ok_or(BuildError::AmountOverflow)?;
    let change_amount = total_selected
        .checked_sub(amount_micronoid)
        .and_then(|remaining| remaining.checked_sub(fee_micronoid))
        .ok_or(BuildError::InsufficientFunds {
            need: amount_micronoid
                .checked_add(fee_micronoid)
                .ok_or(BuildError::AmountOverflow)?,
            have: total_selected,
        })?;

    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    outputs[0] = TxOutput {
        slot_index: data.output_slot_hints[0],
        amount: amount_micronoid,
        owner: Address(to_address),
    };
    let mut validity_bitmap = output_bitmap_bit(0);
    if change_amount > 0 {
        outputs[1] = TxOutput {
            slot_index: data.output_slot_hints[1],
            amount: change_amount,
            owner: data.change_address,
        };
        validity_bitmap |= output_bitmap_bit(1);
    }

    // -----------------------------------------------------------------------
    // Build the fixed input bank. Dead records stay canonical all-zero.
    // -----------------------------------------------------------------------
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    for (index, utxo) in data.selected_utxos.iter().enumerate() {
        inputs[index] = TxInput {
            slot_index: utxo.slot_index,
            amount: utxo.value,
            creation_id: utxo.creation_id,
        };
        validity_bitmap |= 1u16 << index;
    }

    // -----------------------------------------------------------------------
    // Assemble TxBody and run wallet authorization generation.
    //
    // owner_auth_witness is consumed here and zeroized when proving returns.
    // -----------------------------------------------------------------------
    let body = TxBody {
        epoch_anchor: data.epoch_anchor,
        fee: fee_micronoid,
        input_owner: data.change_address,
        inputs,
        outputs,
        validity_bitmap,
        is_coinbase: false,
    };
    let txid = body.txid();

    let bundle = prove_tx(&body, data.owner_auth_witness)
        .map_err(|e| BuildError::ProveFailed(e.to_string()))?;

    let authorization_bytes = bundle
        .to_bytes()
        .map_err(|e| BuildError::ProveFailed(e.to_string()))?;

    // -----------------------------------------------------------------------
    // Assemble the minimal TxIntent. A second claims/slot copy would be
    // redundant and malleable; validators derive it from `body`.
    // -----------------------------------------------------------------------
    let intent = TxIntent::new(body, authorization_bytes);
    debug_assert_eq!(intent.txid(), txid);

    Ok((intent.txid().0, intent.to_bytes()))
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

    fn extract_exact(
        wallet: &WalletState,
        input_slots: &[u32],
        output_amount: u64,
        change: Option<u64>,
        fee: u64,
    ) -> Result<TxBuildData, BuildError> {
        extract_exact_active_inputs_data(
            wallet,
            input_slots,
            output_amount,
            change,
            fee,
            [0x11; 32],
            vec![50_000, 50_001],
            24,
            &std::collections::HashSet::new(),
        )
    }

    #[test]
    fn extract_build_data_accepts_eight_inputs() {
        let (_dir, wallet) = wallet_with_utxos(8, 1_000);
        let data = extract_for(&wallet, 7_500, 500).unwrap();
        assert_eq!(data.selected_utxos.len(), TX_INPUTS);
    }

    #[test]
    fn extract_build_data_rejects_more_than_eight_inputs() {
        let (_dir, wallet) = wallet_with_utxos(9, 1_000);
        let err = match extract_for(&wallet, 9_000, 0) {
            Ok(_) => panic!("expected too many inputs error"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            BuildError::TooManyInputs {
                selected: 9,
                max: 8
            }
        ));
    }

    #[test]
    fn standard_builder_keeps_secret_only_in_owner_witness() {
        let (_dir, wallet) = wallet_with_utxos(1, 20_000);
        let raw_secret = wallet.spend_secret_for(0).0;
        let data = extract_for(&wallet, 10_000, 1_000).unwrap();

        let (txid, intent_bytes) =
            build_and_prove_tx([0xA7; 32], 10_000, 1_000, data).expect("prove standard wallet tx");
        let intent = TxIntent::from_bytes(&intent_bytes).expect("decode standard intent");

        assert_eq!(intent.txid().0, txid);
        assert!(
            !intent_bytes
                .windows(raw_secret.len())
                .any(|window| window == raw_secret),
            "public intent serialized the active owner's spend secret"
        );
        let bundle = noid_gkr::WalletAuthorizationBundle::from_bytes(&intent.authorization_bytes)
            .expect("decode standard authorization bundle");
        noid_gkr::verify_wallet_authorization(&intent.tx_body, &bundle)
            .expect("verify standard authorization bundle");
    }

    #[test]
    fn exact_consolidation_builds_target_and_optional_active_change() {
        let (_dir, wallet) = wallet_with_utxos(2, 100_000);
        let data = extract_exact(&wallet, &[1, 0], 150_000, Some(40_000), 10_000)
            .expect("capture exact plan inputs");
        let active_address = wallet.active_address();
        assert_eq!(
            data.selected_utxos
                .iter()
                .map(|utxo| utxo.slot_index)
                .collect::<Vec<_>>(),
            vec![1, 0]
        );

        let (_txid, bytes) =
            build_and_prove_tx(active_address.0, 150_000, 10_000, data).expect("prove exact plan");
        let intent = TxIntent::from_bytes(&bytes).expect("decode exact-plan intent");
        let outputs: Vec<TxOutput> = intent
            .tx_body
            .live_outputs()
            .map(|(_, output)| *output)
            .collect();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].amount, 150_000);
        assert_eq!(outputs[1].amount, 40_000);
        assert!(outputs.iter().all(|output| output.owner == active_address));
    }

    #[test]
    fn exact_consolidation_rejects_pending_inactive_and_unconfirmed_inputs() {
        let (_dir, mut wallet) = wallet_with_utxos(3, 100_000);
        wallet.pending_input_slots.insert(0);
        assert!(matches!(
            extract_exact(&wallet, &[0], 90_000, None, 10_000),
            Err(BuildError::ExactInputPending { slot_index: 0 })
        ));

        wallet.utxos.get_mut(&1).unwrap().key_index = 1;
        wallet.utxos.get_mut(&1).unwrap().address = wallet.address_at(1);
        assert!(matches!(
            extract_exact(&wallet, &[1], 90_000, None, 10_000),
            Err(BuildError::ActiveOwnerMismatch)
        ));

        wallet.utxos.get_mut(&2).unwrap().confirmed_height = 0;
        assert!(matches!(
            extract_exact(&wallet, &[2], 90_000, None, 10_000),
            Err(BuildError::ExactInputUnconfirmed { slot_index: 2 })
        ));
    }

    #[test]
    fn exact_consolidation_rejects_plan_build_divergence_and_duplicate_slots() {
        let (_dir, wallet) = wallet_with_utxos(2, 100_000);
        assert!(matches!(
            extract_exact(&wallet, &[0, 1], 150_000, Some(39_999), 10_000),
            Err(BuildError::ExactPlanDiverged {
                input_total_micronoid: 200_000,
                output_and_fee_micronoid: 199_999,
            })
        ));
        assert!(matches!(
            extract_exact(&wallet, &[0, 0], 190_000, None, 10_000),
            Err(BuildError::DuplicateExactInput { slot_index: 0 })
        ));
        assert!(matches!(
            extract_exact(&wallet, &[], 1, None, 0),
            Err(BuildError::InvalidExactInputCount { got: 0, max: 8 })
        ));
        assert!(matches!(
            extract_exact(&wallet, &[0, 1, 2, 3, 4, 5, 6, 7, 8], 1, None, 0),
            Err(BuildError::InvalidExactInputCount { got: 9, max: 8 })
        ));
        assert!(matches!(
            extract_exact(&wallet, &[99], 90_000, None, 10_000),
            Err(BuildError::ExactInputMissing { slot_index: 99 })
        ));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only eight-input proof regression")]
    fn build_and_prove_tx_emits_eight_input_secret_free_intent() {
        let (_dir, wallet) = wallet_with_utxos(8, 20_000);
        let raw_secret = wallet.spend_secret_for(0).0;
        let amount = 140_000;
        let fee = 18_500;
        let data = extract_for(&wallet, amount, fee).unwrap();
        assert_eq!(data.selected_utxos.len(), TX_INPUTS);

        let (tx_hash, intent_bytes) =
            build_and_prove_tx([0xA7; 32], amount, fee, data).expect("prove eight-input wallet tx");
        let intent = TxIntent::from_bytes(&intent_bytes).expect("decode intent");
        assert_eq!(intent.tx_body.live_input_count(), TX_INPUTS);
        let mut creation_ids: Vec<u64> = intent
            .tx_body
            .live_inputs()
            .map(|(_, input)| input)
            .map(|input| input.creation_id)
            .collect();
        creation_ids.sort_unstable();
        assert_eq!(creation_ids, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(intent.txid().0, tx_hash);
        assert!(
            !intent_bytes
                .windows(raw_secret.len())
                .any(|window| window == raw_secret),
            "public intent serialized the active owner's spend secret"
        );

        let bundle = noid_gkr::WalletAuthorizationBundle::from_bytes(&intent.authorization_bytes)
            .expect("decode wallet authorization bundle");
        noid_gkr::verify_wallet_authorization(&intent.tx_body, &bundle)
            .expect("verify eight-input authorization bundle");
    }
}
