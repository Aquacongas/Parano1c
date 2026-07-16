// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transaction builder for the Paranoid wallet.
//!
//! This is the only place that assembles a complete [`PagedSpendIntent`] from UTXOs
//! and one active-owner proving capability. The two-phase API separates
//! lock-holding work (coin selection + witness extraction via
//! [`extract_build_data`]) from the
//! CPU-heavy proving work (via [`build_and_prove_tx`]), so the wallet mutex
//! is held for as short a time as possible.
//!
use noid_gkr::OwnerAuthWitness;
use noid_poseidon2b::primitives::{derive_address, Address};
use noid_tx::{
    output_bitmap_bit,
    types::{TxBody, TxInput, TxOutput},
    PagedSpendIntent, TxPage, MAX_PAGED_SPEND_INPUTS, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT,
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

    #[error("payment needs more than {max} active UTXOs (selected at least {selected})")]
    TooManyInputs { selected: usize, max: usize },

    #[error("not enough output slot hints (need {need}, got {got})")]
    NotEnoughSlots { need: usize, got: usize },

    #[error("proving failed: {0}")]
    ProveFailed(String),

    #[error("selected UTXO set is not owned exclusively by the active address")]
    ActiveOwnerMismatch,

    #[error("wallet amount arithmetic overflow")]
    AmountOverflow,
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
///   canonical PagedSpend transaction.
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
                    selected: MAX_PAGED_SPEND_INPUTS + 1,
                    max: MAX_PAGED_SPEND_INPUTS,
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
/// 2. Pack inputs and outputs densely into fixed Tx8x2 pages.
/// 3. Derive one logical txid from the complete ordered page group.
/// 5. `prove_tx(&pages, owner_auth_witness)` → `WalletAuthorizationBundle`;
///    the one secret is consumed and zeroized inside.
/// 6. Assemble and wire-encode the [`PagedSpendIntent`].
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
    // Pack the dense input bank into the minimum number of fixed Tx8x2 pages.
    // -----------------------------------------------------------------------
    let page_count = data.selected_utxos.len().div_ceil(TX_INPUTS).max(1);
    let mut pages = Vec::with_capacity(page_count);
    for page_index in 0..page_count {
        let mut page_inputs = [TxInput::dummy(); TX_INPUTS];
        let mut page_outputs = [TxOutput::dummy(); TX_OUTPUTS];
        let mut page_bitmap = 0u16;
        for (slot, input) in page_inputs.iter_mut().enumerate() {
            let input_index = page_index * TX_INPUTS + slot;
            if let Some(utxo) = data.selected_utxos.get(input_index) {
                *input = TxInput {
                    slot_index: utxo.slot_index,
                    amount: utxo.value,
                    creation_id: utxo.creation_id,
                };
                page_bitmap |= 1u16 << slot;
            }
        }
        if page_index == 0 {
            page_outputs = outputs;
            page_bitmap |= validity_bitmap;
            page_bitmap |= PAGED_SPEND_START_BIT;
        }
        if page_index + 1 == page_count {
            page_bitmap |= PAGED_SPEND_END_BIT;
        }
        pages.push(
            TxPage::new(TxBody {
                epoch_anchor: data.epoch_anchor,
                fee: if page_index == 0 { fee_micronoid } else { 0 },
                input_owner: data.change_address,
                inputs: page_inputs,
                outputs: page_outputs,
                validity_bitmap: page_bitmap,
                is_coinbase: false,
            })
            .map_err(|error| BuildError::ProveFailed(error.to_string()))?,
        );
    }

    // The owner witness is consumed here and zeroized when proving returns.
    let bundle = prove_tx(&pages, data.owner_auth_witness)
        .map_err(|e| BuildError::ProveFailed(e.to_string()))?;

    let authorization_bytes = bundle
        .to_bytes()
        .map_err(|e| BuildError::ProveFailed(e.to_string()))?;

    // -----------------------------------------------------------------------
    // Assemble the one bounded atomic group. A continuation page is never a
    // separately relayable transaction.
    // -----------------------------------------------------------------------
    let intent = PagedSpendIntent::new(pages, authorization_bytes)
        .map_err(|error| BuildError::ProveFailed(error.to_string()))?;

    Ok((
        intent.logical_txid().0,
        intent
            .to_bytes()
            .map_err(|error| BuildError::ProveFailed(error.to_string()))?,
    ))
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
    fn extract_build_data_accepts_eight_inputs() {
        let (_dir, wallet) = wallet_with_utxos(8, 1_000);
        let data = extract_for(&wallet, 7_500, 500).unwrap();
        assert_eq!(data.selected_utxos.len(), TX_INPUTS);
    }

    #[test]
    fn extract_build_data_accepts_more_than_one_page() {
        let (_dir, wallet) = wallet_with_utxos(9, 1_000);
        let data = extract_for(&wallet, 9_000, 0).unwrap();
        assert_eq!(data.selected_utxos.len(), 9);
    }

    #[test]
    fn extract_build_data_rejects_past_group_input_cap() {
        let count = MAX_PAGED_SPEND_INPUTS as u32 + 1;
        let (_dir, wallet) = wallet_with_utxos(count, 1_000);
        let err = match extract_for(&wallet, count as u64 * 1_000, 0) {
            Ok(_) => panic!("expected PagedSpend input cap error"),
            Err(error) => error,
        };
        assert!(matches!(
            err,
            BuildError::TooManyInputs {
                selected,
                max: MAX_PAGED_SPEND_INPUTS,
            } if selected == MAX_PAGED_SPEND_INPUTS + 1
        ));
    }

    #[test]
    fn multi_page_builder_keeps_secret_only_in_owner_witness() {
        let (_dir, wallet) = wallet_with_utxos(9, 20_000);
        let secret = wallet.spend_secret_for(0);
        let mut raw_secret = secret.with_exposed_prover_fields(|fields| {
            let mut bytes = [0u8; 32];
            bytes[..16].copy_from_slice(&fields[0].0.to_le_bytes());
            bytes[16..].copy_from_slice(&fields[1].0.to_le_bytes());
            bytes
        });
        let data = extract_for(&wallet, 170_000, 1_000).unwrap();

        let (txid, intent_bytes) = build_and_prove_tx([0xA7; 32], 170_000, 1_000, data)
            .expect("prove multi-page wallet tx");
        let intent = PagedSpendIntent::from_bytes(&intent_bytes).expect("decode standard intent");

        assert_eq!(intent.logical_txid().0, txid);
        assert_eq!(intent.pages.len(), 2);
        assert_eq!(
            intent
                .pages
                .iter()
                .map(|page| page.body.live_input_count())
                .sum::<usize>(),
            9
        );
        assert!(
            !intent_bytes
                .windows(raw_secret.len())
                .any(|window| window == raw_secret),
            "public intent serialized the active owner's spend secret"
        );
        zeroize::Zeroize::zeroize(&mut raw_secret);
        let bundle = noid_gkr::WalletAuthorizationBundle::from_bytes(&intent.authorization_bytes)
            .expect("decode standard authorization bundle");
        noid_gkr::verify_paged_spend_authorization(&intent.pages, &bundle)
            .expect("verify standard authorization bundle");
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only eight-input proof regression")]
    fn build_and_prove_tx_emits_eight_input_secret_free_intent() {
        let (_dir, wallet) = wallet_with_utxos(8, 20_000);
        let secret = wallet.spend_secret_for(0);
        let mut raw_secret = secret.with_exposed_prover_fields(|fields| {
            let mut bytes = [0u8; 32];
            bytes[..16].copy_from_slice(&fields[0].0.to_le_bytes());
            bytes[16..].copy_from_slice(&fields[1].0.to_le_bytes());
            bytes
        });
        let amount = 140_000;
        let fee = 18_500;
        let data = extract_for(&wallet, amount, fee).unwrap();
        assert_eq!(data.selected_utxos.len(), TX_INPUTS);

        let (tx_hash, intent_bytes) =
            build_and_prove_tx([0xA7; 32], amount, fee, data).expect("prove eight-input wallet tx");
        let intent = PagedSpendIntent::from_bytes(&intent_bytes).expect("decode intent");
        assert_eq!(intent.pages.len(), 1);
        assert_eq!(intent.pages[0].body.live_input_count(), TX_INPUTS);
        let mut creation_ids: Vec<u64> = intent
            .pages
            .iter()
            .flat_map(|page| page.body.live_inputs())
            .map(|(_, input)| input)
            .map(|input| input.creation_id)
            .collect();
        creation_ids.sort_unstable();
        assert_eq!(creation_ids, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(intent.logical_txid().0, tx_hash);
        assert!(
            !intent_bytes
                .windows(raw_secret.len())
                .any(|window| window == raw_secret),
            "public intent serialized the active owner's spend secret"
        );
        zeroize::Zeroize::zeroize(&mut raw_secret);

        let bundle = noid_gkr::WalletAuthorizationBundle::from_bytes(&intent.authorization_bytes)
            .expect("decode wallet authorization bundle");
        noid_gkr::verify_paged_spend_authorization(&intent.pages, &bundle)
            .expect("verify eight-input authorization bundle");
    }
}
