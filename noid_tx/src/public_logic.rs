// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact public transaction predicate for wallet-originated transactions.
//!
//! Wallets do not transmit a public-arithmetic proof. Mempool and block
//! validation deterministically rebuild these facts from `TxBody`, while the
//! authorization proof handles ownership.

use noid_poseidon2b::primitives::TxBodyHash;

use crate::{hash_tx_body_for_shape, TxBody, TxShape};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicLogicFacts {
    pub tx_body_hash: TxBodyHash,
    pub fee_u64: u64,
    pub n_live_inputs: u8,
    pub n_live_outputs: u8,
    pub input_sum: u128,
    pub output_sum: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicLogicError {
    Coinbase,
    UnsupportedShape(TxShape),
    TooManyInputs {
        actual: usize,
        max: usize,
    },
    TooManyOutputs {
        actual: usize,
        max: usize,
    },
    FeeTooLarge {
        fee: u128,
    },
    /// A `valid = false` entry carries non-dummy content (canonicality:
    /// dead entries are the zero pattern, matching the committed bitmap).
    DeadEntryNotDummy {
        index: usize,
    },
    /// Live inputs owned by more than one address (consensus: one owner
    /// group per transaction — wallets spend from one active address).
    MultipleInputOwners,
    InputSumOverflow,
    OutputSumOverflow,
    OutputPlusFeeOverflow,
    BalanceMismatch {
        input_sum: u128,
        output_sum: u128,
        fee: u128,
    },
    NoLiveInputs,
    LiveInputCountTooLarge {
        actual: usize,
    },
    LiveOutputCountTooLarge {
        actual: usize,
    },
}

impl std::fmt::Display for PublicLogicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PublicLogicError {}

/// The SHARED body-semantics predicate — every consensus entrypoint
/// (proof-native block validation, the sequential interpreter, mempool
/// admission) calls THIS, so no path can accept a body another path
/// rejects. No hashing (the 59-perm body hash is computed only where a
/// caller needs it). Covers BOTH user transactions and the coinbase:
///
/// - shape support + input/output length bounds (both);
/// - dead-entry canonicality: `valid = false` ⇒ the dummy zero pattern
///   (both — the committed bitmap marks exactly the semantic leaves);
/// - user tx: fee fits u64, live counts fit, at least one live input,
///   ONE OWNER PER TRANSACTION, inputs balance outputs + fee;
/// - coinbase: zero fee, NO live inputs, exactly one live output.
pub fn validate_body_semantics_no_hash(body: &TxBody) -> Result<(), PublicLogicError> {
    if !body.shape.proof_supported() {
        return Err(PublicLogicError::UnsupportedShape(body.shape));
    }

    let max_inputs = body.shape.max_inputs();
    if body.inputs.len() > max_inputs {
        return Err(PublicLogicError::TooManyInputs {
            actual: body.inputs.len(),
            max: max_inputs,
        });
    }
    let max_outputs = body.shape.max_outputs();
    if body.outputs.len() > max_outputs {
        return Err(PublicLogicError::TooManyOutputs {
            actual: body.outputs.len(),
            max: max_outputs,
        });
    }

    // Canonicality: a dead entry carries dummy content — the committed
    // liveness bitmap (the body hash's reserved leaf) is then exactly the
    // "which leaves are semantic" selector and dead leaves are the zero
    // pattern everywhere (native and in-trace). Applies to the coinbase
    // too.
    for (i, input) in body.inputs.iter().enumerate() {
        if !input.valid
            && (input.slot_index != 0
                || input.value != 0
                || input.creation_id != 0
                || input.owner.0 != [0u8; 32])
        {
            return Err(PublicLogicError::DeadEntryNotDummy { index: i });
        }
    }
    for (j, output) in body.outputs.iter().enumerate() {
        if !output.valid
            && (output.slot_index != 0 || output.value != 0 || output.owner.0 != [0u8; 32])
        {
            return Err(PublicLogicError::DeadEntryNotDummy { index: j });
        }
    }

    let n_live_inputs_usize = body.inputs.iter().filter(|i| i.valid).count();
    let n_live_outputs_usize = body.outputs.iter().filter(|o| o.valid).count();

    if body.is_coinbase {
        if body.fee != 0 {
            return Err(PublicLogicError::FeeTooLarge { fee: body.fee });
        }
        if n_live_inputs_usize != 0 {
            return Err(PublicLogicError::LiveInputCountTooLarge {
                actual: n_live_inputs_usize,
            });
        }
        if n_live_outputs_usize != 1 {
            return Err(PublicLogicError::LiveOutputCountTooLarge {
                actual: n_live_outputs_usize,
            });
        }
        return Ok(());
    }

    u64::try_from(body.fee).map_err(|_| PublicLogicError::FeeTooLarge { fee: body.fee })?;

    let n_live_inputs = u8::try_from(n_live_inputs_usize).map_err(|_| {
        PublicLogicError::LiveInputCountTooLarge {
            actual: n_live_inputs_usize,
        }
    })?;
    if n_live_inputs == 0 {
        return Err(PublicLogicError::NoLiveInputs);
    }
    u8::try_from(n_live_outputs_usize).map_err(|_| PublicLogicError::LiveOutputCountTooLarge {
        actual: n_live_outputs_usize,
    })?;

    // ONE OWNER PER TRANSACTION (consensus rule): every live input is
    // owned by the same address. Wallets operate one active address at a
    // time (per-address balances; cross-address moves are explicit
    // transactions), spending never proves common ownership of two
    // addresses, and the owner-auth statement always carries exactly one
    // owner group — so the proof layout (hence the recursive block class
    // shape) is owner-count independent by construction.
    let mut live_owner: Option<&noid_poseidon2b::primitives::Address> = None;
    for input in body.inputs.iter().filter(|i| i.valid) {
        match live_owner {
            None => live_owner = Some(&input.owner),
            Some(owner) if *owner == input.owner => {}
            Some(_) => return Err(PublicLogicError::MultipleInputOwners),
        }
    }

    let mut input_sum = 0u128;
    for input in body.inputs.iter().filter(|i| i.valid) {
        input_sum = input_sum
            .checked_add(input.value as u128)
            .ok_or(PublicLogicError::InputSumOverflow)?;
    }
    let mut output_sum = 0u128;
    for output in body.outputs.iter().filter(|o| o.valid) {
        output_sum = output_sum
            .checked_add(output.value as u128)
            .ok_or(PublicLogicError::OutputSumOverflow)?;
    }
    let rhs = output_sum
        .checked_add(body.fee)
        .ok_or(PublicLogicError::OutputPlusFeeOverflow)?;
    if input_sum != rhs {
        return Err(PublicLogicError::BalanceMismatch {
            input_sum,
            output_sum,
            fee: body.fee,
        });
    }
    Ok(())
}

pub fn validate_public_tx_logic(body: &TxBody) -> Result<PublicLogicFacts, PublicLogicError> {
    if body.is_coinbase {
        return Err(PublicLogicError::Coinbase);
    }
    validate_body_semantics_no_hash(body)?;

    // The facts (already range-checked above).
    let fee_u64 = body.fee as u64;
    let n_live_inputs = body.inputs.iter().filter(|i| i.valid).count() as u8;
    let n_live_outputs = body.outputs.iter().filter(|o| o.valid).count() as u8;
    let input_sum: u128 = body
        .inputs
        .iter()
        .filter(|i| i.valid)
        .map(|i| i.value as u128)
        .sum();
    let output_sum: u128 = body
        .outputs
        .iter()
        .filter(|o| o.valid)
        .map(|o| o.value as u128)
        .sum();

    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );

    Ok(PublicLogicFacts {
        tx_body_hash,
        fee_u64,
        n_live_inputs,
        n_live_outputs,
        input_sum,
        output_sum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TxInput, TxOutput};
    use noid_poseidon2b::primitives::{Address, SpendSecret};

    fn input(slot: u32, value: u64, valid: bool) -> TxInput {
        TxInput {
            slot_index: slot,
            value,
            creation_id: 0,
            // One owner per tx (consensus): live inputs share an address;
            // dead entries carry the dummy zero pattern.
            owner: if valid {
                Address([7u8; 32])
            } else {
                Address([0u8; 32])
            },
            spend_secret: SpendSecret([0u8; 32]),
            valid,
        }
    }

    fn output(slot: u32, value: u64, valid: bool) -> TxOutput {
        TxOutput {
            slot_index: slot,
            value,
            owner: if valid {
                Address([slot as u8; 32])
            } else {
                Address([0u8; 32])
            },
            valid,
        }
    }

    #[test]
    fn standard_balanced_body_accepts() {
        let body = TxBody::standard(
            [1u8; 32],
            7,
            vec![input(1, 100, true), input(2, 50, true)],
            vec![output(10, 143, true)],
            false,
        );
        let facts = validate_public_tx_logic(&body).expect("valid body");
        assert_eq!(facts.fee_u64, 7);
        assert_eq!(facts.n_live_inputs, 2);
        assert_eq!(facts.n_live_outputs, 1);
        assert_eq!(facts.input_sum, 150);
        assert_eq!(facts.output_sum, 143);
    }

    #[test]
    fn dead_entries_are_dummy_and_ignored_for_balance() {
        // Canonical dead entries (dummy content) are accepted and excluded
        // from the balance.
        let body = TxBody::standard(
            [2u8; 32],
            1,
            vec![input(1, 10, true), input(0, 0, false)],
            vec![output(10, 9, true), output(0, 0, false)],
            false,
        );
        let facts = validate_public_tx_logic(&body).expect("valid body");
        assert_eq!(facts.input_sum, 10);
        assert_eq!(facts.output_sum, 9);
    }

    #[test]
    fn dead_entry_with_content_rejects() {
        // A dead entry smuggling non-dummy content violates canonicality
        // (the committed bitmap marks exactly the semantic leaves).
        let body = TxBody::standard(
            [2u8; 32],
            1,
            vec![input(1, 10, true), input(2, u64::MAX, false)],
            vec![output(10, 9, true)],
            false,
        );
        assert!(matches!(
            validate_public_tx_logic(&body),
            Err(PublicLogicError::DeadEntryNotDummy { index: 1 })
        ));
    }

    #[test]
    fn dead_input_with_creation_id_rejects() {
        let mut dead = input(0, 0, false);
        dead.creation_id = 1;
        let body = TxBody::standard(
            [2u8; 32],
            1,
            vec![input(1, 10, true), dead],
            vec![output(10, 9, true)],
            false,
        );
        assert_eq!(
            validate_public_tx_logic(&body),
            Err(PublicLogicError::DeadEntryNotDummy { index: 1 })
        );
    }

    #[test]
    fn multiple_input_owners_reject() {
        // Consensus: live inputs must share one owner address.
        let mut i2 = input(2, 5, true);
        i2.owner = Address([9u8; 32]);
        let body = TxBody::standard(
            [2u8; 32],
            0,
            vec![input(1, 10, true), i2],
            vec![output(10, 15, true)],
            false,
        );
        assert_eq!(
            validate_public_tx_logic(&body),
            Err(PublicLogicError::MultipleInputOwners)
        );
    }

    #[test]
    fn imbalance_rejects() {
        let body = TxBody::standard(
            [3u8; 32],
            1,
            vec![input(1, 10, true)],
            vec![output(10, 10, true)],
            false,
        );
        assert!(matches!(
            validate_public_tx_logic(&body),
            Err(PublicLogicError::BalanceMismatch { .. })
        ));
    }

    #[test]
    fn sweep_balanced_body_accepts() {
        let body = TxBody {
            shape: TxShape::Sweep25x2,
            epoch_anchor: [4u8; 32],
            fee: 5,
            inputs: (0..5).map(|i| input(i, 20, true)).collect(),
            outputs: vec![output(100, 95, true), output(0, 0, false)],
            is_coinbase: false,
        };
        let facts = validate_public_tx_logic(&body).expect("valid sweep body");
        assert_eq!(facts.n_live_inputs, 5);
        assert_eq!(facts.n_live_outputs, 1);
        assert_eq!(facts.input_sum, 100);
        assert_eq!(facts.output_sum, 95);
    }

    #[test]
    fn coinbase_rejects() {
        let body = TxBody::standard([0u8; 32], 0, vec![], vec![], true);
        assert_eq!(
            validate_public_tx_logic(&body),
            Err(PublicLogicError::Coinbase)
        );
    }

    #[test]
    fn zero_input_non_coinbase_rejects() {
        let body = TxBody::standard([5u8; 32], 0, vec![], vec![], false);
        assert_eq!(
            validate_public_tx_logic(&body),
            Err(PublicLogicError::NoLiveInputs)
        );
    }

    #[test]
    fn fee_too_large_rejects() {
        let body = TxBody::standard(
            [0u8; 32],
            u64::MAX as u128 + 1,
            vec![input(1, 1, true)],
            vec![],
            false,
        );
        assert!(matches!(
            validate_public_tx_logic(&body),
            Err(PublicLogicError::FeeTooLarge { .. })
        ));
    }
}
