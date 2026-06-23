// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact public transaction predicate for wallet-originated transactions.
//!
//! This checker replaces the wallet-transmitted public-arithmetic STARK at
//! mempool admission. It does not replace the canonical block-side TxLogic AIR:
//! block proving still rebuilds and proves that relation from `TxBody`.

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
    InputSumOverflow,
    OutputSumOverflow,
    OutputPlusFeeOverflow,
    BalanceMismatch {
        input_sum: u128,
        output_sum: u128,
        fee: u128,
    },
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

pub fn validate_public_tx_logic(body: &TxBody) -> Result<PublicLogicFacts, PublicLogicError> {
    if body.is_coinbase {
        return Err(PublicLogicError::Coinbase);
    }
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

    let fee_u64 =
        u64::try_from(body.fee).map_err(|_| PublicLogicError::FeeTooLarge { fee: body.fee })?;

    let n_live_inputs_usize = body.inputs.iter().filter(|i| i.valid).count();
    let n_live_outputs_usize = body.outputs.iter().filter(|o| o.valid).count();
    let n_live_inputs = u8::try_from(n_live_inputs_usize).map_err(|_| {
        PublicLogicError::LiveInputCountTooLarge {
            actual: n_live_inputs_usize,
        }
    })?;
    let n_live_outputs = u8::try_from(n_live_outputs_usize).map_err(|_| {
        PublicLogicError::LiveOutputCountTooLarge {
            actual: n_live_outputs_usize,
        }
    })?;

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
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};

    fn input(slot: u32, value: u64, valid: bool) -> TxInput {
        TxInput {
            slot_index: slot,
            value,
            owner: Address([slot as u8; 32]),
            spend_secret: SpendSecret([0u8; 32]),
            auth_tag: AuthTag([0u8; 32]),
            valid,
        }
    }

    fn output(slot: u32, value: u64, valid: bool) -> TxOutput {
        TxOutput {
            slot_index: slot,
            value,
            owner: Address([slot as u8; 32]),
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
    fn invalid_entries_are_ignored_for_balance() {
        let body = TxBody::standard(
            [2u8; 32],
            1,
            vec![input(1, 10, true), input(2, u64::MAX, false)],
            vec![output(10, 9, true), output(11, u64::MAX, false)],
            false,
        );
        let facts = validate_public_tx_logic(&body).expect("valid body");
        assert_eq!(facts.input_sum, 10);
        assert_eq!(facts.output_sum, 9);
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
            outputs: vec![output(100, 95, true), output(101, 0, false)],
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
