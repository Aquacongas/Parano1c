// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Research-only one-capsule boundary for a complete PagedSpend group.
//!
//! This is a narrow composition of the production capsule primitive. It does
//! not create a second proof protocol and never exposes a reusable state table.

use noid_gkr::evaluate_permutation;
use noid_gkr::zk_auth_capsule::ZkAuthCapsuleStateTable;
use noid_gkr::zk_authorization::{
    prove_zk_authorization_from_state_table, verify_zk_authorization, ZkAuthCapsuleOwnerStatement,
    ZkAuthorizationProof,
};
use noid_poseidon2b::native::{capacity_iv, TAG_ADDRFIX};
use noid_poseidon2b::primitives::SpendSecret;
use zeroize::Zeroize;

use crate::paged_spend::{canonical_paged_spend_auth, PagedSpendError, TxPage};

/// Move-only wallet authority for one research proof attempt.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PagedSpendAuthorizationWitness {
    spend_secret: SpendSecret,
}

impl PagedSpendAuthorizationWitness {
    pub fn new(spend_secret: SpendSecret) -> Self {
        Self { spend_secret }
    }
}

#[derive(Debug)]
pub enum PagedSpendAuthorizationError {
    Group(PagedSpendError),
    OwnerBoundaryMismatch,
    StateTable,
    Prove,
    Verify,
}

impl std::fmt::Display for PagedSpendAuthorizationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PagedSpendAuthorizationError {}

fn capsule_statement(pages: &[TxPage]) -> Result<ZkAuthCapsuleOwnerStatement, PagedSpendError> {
    let canonical = canonical_paged_spend_auth(pages)?;
    Ok(ZkAuthCapsuleOwnerStatement {
        tx_body_hash: canonical.logical_txid.as_fields(),
        address: canonical.input_owner.as_fields(),
    })
}

/// Produce the unchanged witness-hiding capsule for one complete page group.
pub fn prove_paged_spend_authorization(
    pages: &[TxPage],
    witness: PagedSpendAuthorizationWitness,
) -> Result<ZkAuthorizationProof, PagedSpendAuthorizationError> {
    let statement = capsule_statement(pages).map_err(PagedSpendAuthorizationError::Group)?;
    let iv = capacity_iv(TAG_ADDRFIX);
    let permutation = witness.spend_secret.with_exposed_prover_fields(|secret| {
        let mut permutation_input = [secret[0], secret[1], iv[0], iv[1]];
        let permutation = evaluate_permutation(permutation_input);
        permutation_input.zeroize();
        permutation
    });
    if permutation.final_state()[..2] != statement.address {
        return Err(PagedSpendAuthorizationError::OwnerBoundaryMismatch);
    }
    let state = ZkAuthCapsuleStateTable::from_permutation_witness(&permutation)
        .map_err(|_| PagedSpendAuthorizationError::StateTable)?;
    prove_zk_authorization_from_state_table(&state, statement)
        .map_err(|_| PagedSpendAuthorizationError::Prove)
}

/// Verify a complete group's capsule against its logical txid and owner.
pub fn verify_paged_spend_authorization(
    pages: &[TxPage],
    proof: &ZkAuthorizationProof,
) -> Result<(), PagedSpendAuthorizationError> {
    let statement = capsule_statement(pages).map_err(PagedSpendAuthorizationError::Group)?;
    verify_zk_authorization(statement, proof)
        .map(|_| ())
        .map_err(|_| PagedSpendAuthorizationError::Verify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paged_spend::{PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT};
    use noid_poseidon2b::primitives::{derive_address, Address};
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn secret_bytes(seed: u8) -> [u8; 32] {
        std::array::from_fn(|index| seed.wrapping_mul(29).wrapping_add(index as u8))
    }

    fn owner(bytes: [u8; 32]) -> Address {
        derive_address(&SpendSecret::from_bytes(bytes))
    }

    fn one_page(bytes: [u8; 32], statement_seed: u8) -> Vec<TxPage> {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: u32::from(statement_seed) + 1,
            amount: 11,
            creation_id: 7,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: u32::from(statement_seed) + 10_000,
            amount: 10,
            owner: Address([statement_seed.wrapping_add(1); 32]),
        };
        vec![TxPage::new(TxBody {
            epoch_anchor: [statement_seed; 32],
            fee: 1,
            input_owner: owner(bytes),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        })
        .unwrap()]
    }

    #[test]
    fn same_secret_two_statements_use_distinct_capsules_and_cross_reject() {
        let bytes = secret_bytes(17);
        let first_pages = one_page(bytes, 3);
        let second_pages = one_page(bytes, 4);
        let first = prove_paged_spend_authorization(
            &first_pages,
            PagedSpendAuthorizationWitness::new(SpendSecret::from_bytes(bytes)),
        )
        .unwrap();
        let second = prove_paged_spend_authorization(
            &second_pages,
            PagedSpendAuthorizationWitness::new(SpendSecret::from_bytes(bytes)),
        )
        .unwrap();

        verify_paged_spend_authorization(&first_pages, &first).unwrap();
        verify_paged_spend_authorization(&second_pages, &second).unwrap();
        assert_ne!(first.to_bytes().unwrap(), second.to_bytes().unwrap());
        assert!(verify_paged_spend_authorization(&first_pages, &second).is_err());
        assert!(verify_paged_spend_authorization(&second_pages, &first).is_err());
    }
}
