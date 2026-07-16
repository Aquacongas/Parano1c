// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Class-aware block-stream harness over the production PagedSpend primitive.
//!
//! Group encoding, hashing and semantic validation live only in `noid_tx`.
//! This research adapter checks the future consensus boundary that cannot live
//! in `noid_tx` without creating a dependency cycle: B64/B255 selection,
//! aggregate resource caps and cross-group slot uniqueness.

use std::collections::HashSet;

pub use noid_tx::{
    canonical_paged_spend_auth, hash_paged_spend, validate_paged_spend, CanonicalPagedSpendAuth,
    PagedSpendError, PagedSpendFacts, PagedSpendIntent, TxPage, MAX_PAGED_SPEND_INPUTS,
    MAX_PAGED_SPEND_INTENT_BYTES, MAX_PAGED_SPEND_OUTPUTS, MAX_PAGED_SPEND_PAGES,
    PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT,
};

use crate::geometry::{
    ProofClass, B255_INPUT_CAPACITY, B255_LIVE_AUTHORIZATION_CAPACITY, B255_OUTPUT_CAPACITY,
    B255_PAGE_CAPACITY,
};

pub const MAX_BLOCK_USER_PAGES: usize = B255_PAGE_CAPACITY;
pub const MAX_BLOCK_LOGICAL_TRANSACTIONS: usize = B255_LIVE_AUTHORIZATION_CAPACITY;
pub const MAX_BLOCK_LIVE_INPUTS: usize = B255_INPUT_CAPACITY;
pub const MAX_BLOCK_LIVE_OUTPUTS: usize = B255_OUTPUT_CAPACITY;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedSpendStreamFacts {
    pub proof_class: ProofClass,
    pub groups: Vec<PagedSpendFacts>,
    pub page_count: u16,
    pub logical_count: u16,
    pub live_inputs: u16,
    pub live_outputs: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PagedSpendStreamError {
    Group(PagedSpendError),
    BlockPageLimit {
        actual: usize,
        capacity: usize,
    },
    ProofClassMismatch {
        expected: ProofClass,
        actual: ProofClass,
    },
    UnterminatedGroup {
        start_page: usize,
    },
    TooManyGroups {
        actual: usize,
        capacity: usize,
    },
    BlockInputLimit {
        actual: usize,
        capacity: usize,
    },
    BlockOutputLimit {
        actual: usize,
        capacity: usize,
    },
    DuplicateInputSlot {
        slot: u32,
    },
    DuplicateOutputSlot {
        slot: u32,
    },
    InputOutputSlotOverlap {
        slot: u32,
    },
}

impl From<PagedSpendError> for PagedSpendStreamError {
    fn from(error: PagedSpendError) -> Self {
        Self::Group(error)
    }
}

impl std::fmt::Display for PagedSpendStreamError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PagedSpendStreamError {}

pub fn validate_paged_spend_stream(
    pages: &[TxPage],
) -> Result<PagedSpendStreamFacts, PagedSpendStreamError> {
    let Some(proof_class) = ProofClass::for_page_count(pages.len()) else {
        return Err(PagedSpendStreamError::BlockPageLimit {
            actual: pages.len(),
            capacity: MAX_BLOCK_USER_PAGES,
        });
    };
    validate_paged_spend_stream_for_class(pages, proof_class)
}

pub fn validate_paged_spend_stream_for_class(
    pages: &[TxPage],
    proof_class: ProofClass,
) -> Result<PagedSpendStreamFacts, PagedSpendStreamError> {
    if pages.len() > proof_class.page_capacity() {
        return Err(PagedSpendStreamError::BlockPageLimit {
            actual: pages.len(),
            capacity: proof_class.page_capacity(),
        });
    }
    let expected =
        ProofClass::for_page_count(pages.len()).ok_or(PagedSpendStreamError::BlockPageLimit {
            actual: pages.len(),
            capacity: MAX_BLOCK_USER_PAGES,
        })?;
    if expected != proof_class {
        return Err(PagedSpendStreamError::ProofClassMismatch {
            expected,
            actual: proof_class,
        });
    }

    let mut groups = Vec::with_capacity(pages.len());
    let mut cursor = 0usize;
    while cursor < pages.len() {
        let start = cursor;
        let Some(relative_end) = pages[start..].iter().position(TxPage::is_end) else {
            return Err(PagedSpendStreamError::UnterminatedGroup { start_page: start });
        };
        let end = start + relative_end + 1;
        groups.push(validate_paged_spend(&pages[start..end])?);
        if groups.len() > proof_class.live_authorization_capacity() {
            return Err(PagedSpendStreamError::TooManyGroups {
                actual: groups.len(),
                capacity: proof_class.live_authorization_capacity(),
            });
        }
        cursor = end;
    }

    let live_inputs = groups.iter().try_fold(0usize, |sum, group| {
        sum.checked_add(group.live_inputs as usize)
    });
    let live_inputs = live_inputs.ok_or(PagedSpendStreamError::BlockInputLimit {
        actual: usize::MAX,
        capacity: proof_class.input_capacity(),
    })?;
    if live_inputs > proof_class.input_capacity() {
        return Err(PagedSpendStreamError::BlockInputLimit {
            actual: live_inputs,
            capacity: proof_class.input_capacity(),
        });
    }

    let live_outputs = groups.iter().try_fold(0usize, |sum, group| {
        sum.checked_add(group.live_outputs as usize)
    });
    let live_outputs = live_outputs.ok_or(PagedSpendStreamError::BlockOutputLimit {
        actual: usize::MAX,
        capacity: proof_class.output_capacity(),
    })?;
    if live_outputs > proof_class.output_capacity() {
        return Err(PagedSpendStreamError::BlockOutputLimit {
            actual: live_outputs,
            capacity: proof_class.output_capacity(),
        });
    }

    let mut input_slots = HashSet::with_capacity(live_inputs);
    let mut output_slots = HashSet::with_capacity(live_outputs);
    for page in pages {
        for (_, input) in page.body.live_inputs() {
            if !input_slots.insert(input.slot_index) {
                return Err(PagedSpendStreamError::DuplicateInputSlot {
                    slot: input.slot_index,
                });
            }
        }
        for (_, output) in page.body.live_outputs() {
            if !output_slots.insert(output.slot_index) {
                return Err(PagedSpendStreamError::DuplicateOutputSlot {
                    slot: output.slot_index,
                });
            }
        }
    }
    if let Some(slot) = input_slots.intersection(&output_slots).next() {
        return Err(PagedSpendStreamError::InputOutputSlotOverlap { slot: *slot });
    }

    Ok(PagedSpendStreamFacts {
        proof_class,
        page_count: pages.len() as u16,
        logical_count: groups.len() as u16,
        live_inputs: live_inputs as u16,
        live_outputs: live_outputs as u16,
        groups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn one_page(index: usize) -> TxPage {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: index as u32 + 1,
            amount: 10,
            creation_id: index as u64 + 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 10_000 + index as u32,
            amount: 9,
            owner: Address([index as u8; 32]),
        };
        TxPage::new(TxBody {
            epoch_anchor: [index as u8; 32],
            fee: 1,
            input_owner: Address([0x42; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        })
        .unwrap()
    }

    fn independent_stream(count: usize) -> Vec<TxPage> {
        (0..count).map(one_page).collect()
    }

    fn maximum_group() -> Vec<TxPage> {
        const INPUTS: usize = 1_020;
        const INPUT_AMOUNT: u64 = 1_000;
        const FEE: u64 = 5;
        let owner = Address([0xA5; 32]);
        (0..MAX_PAGED_SPEND_PAGES)
            .map(|page_index| {
                let mut inputs = [TxInput::dummy(); TX_INPUTS];
                let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
                let mut bitmap = 0u16;
                for (slot, input) in inputs.iter_mut().enumerate() {
                    let index = page_index * TX_INPUTS + slot;
                    if index < INPUTS {
                        *input = TxInput {
                            slot_index: index as u32 + 1,
                            amount: INPUT_AMOUNT,
                            creation_id: index as u64 + 1,
                        };
                        bitmap |= 1 << slot;
                    }
                }
                if page_index == 0 {
                    outputs[0] = TxOutput {
                        slot_index: 1_000_000,
                        amount: INPUTS as u64 * INPUT_AMOUNT - FEE,
                        owner,
                    };
                    bitmap |= output_bitmap_bit(0) | PAGED_SPEND_START_BIT;
                }
                if page_index + 1 == MAX_PAGED_SPEND_PAGES {
                    bitmap |= PAGED_SPEND_END_BIT;
                }
                TxPage::new(TxBody {
                    epoch_anchor: [0x5A; 32],
                    fee: if page_index == 0 { FEE } else { 0 },
                    input_owner: owner,
                    inputs,
                    outputs,
                    validity_bitmap: bitmap,
                    is_coinbase: false,
                })
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn class_boundary_is_exact_at_64_65_and_255() {
        for (count, class) in [
            (0, ProofClass::B64),
            (64, ProofClass::B64),
            (65, ProofClass::B255),
            (255, ProofClass::B255),
        ] {
            let stream = independent_stream(count);
            let facts = validate_paged_spend_stream(&stream).unwrap();
            assert_eq!(facts.proof_class, class);
            assert_eq!(facts.page_count as usize, count);
            assert_eq!(facts.logical_count as usize, count);
        }

        assert_eq!(
            validate_paged_spend_stream_for_class(&independent_stream(64), ProofClass::B255),
            Err(PagedSpendStreamError::ProofClassMismatch {
                expected: ProofClass::B64,
                actual: ProofClass::B255,
            })
        );
        assert_eq!(
            validate_paged_spend_stream_for_class(&independent_stream(65), ProofClass::B64),
            Err(PagedSpendStreamError::BlockPageLimit {
                actual: 65,
                capacity: 64,
            })
        );
        assert_eq!(
            validate_paged_spend_stream(&independent_stream(256)),
            Err(PagedSpendStreamError::BlockPageLimit {
                actual: 256,
                capacity: 255,
            })
        );
    }

    #[test]
    fn partial_groups_and_cross_group_conflicts_reject() {
        let mut partial = independent_stream(1);
        partial[0].body.validity_bitmap &= !PAGED_SPEND_END_BIT;
        assert_eq!(
            validate_paged_spend_stream(&partial),
            Err(PagedSpendStreamError::UnterminatedGroup { start_page: 0 })
        );

        let mut conflict = independent_stream(2);
        conflict[1].body.inputs[0].slot_index = conflict[0].body.inputs[0].slot_index;
        assert_eq!(
            validate_paged_spend_stream(&conflict),
            Err(PagedSpendStreamError::DuplicateInputSlot { slot: 1 })
        );
    }

    #[test]
    fn maximum_group_is_indivisible_and_requires_b255() {
        let group = maximum_group();
        assert_eq!(
            validate_paged_spend_stream_for_class(&group, ProofClass::B64),
            Err(PagedSpendStreamError::BlockPageLimit {
                actual: 128,
                capacity: 64,
            })
        );
        let facts =
            validate_paged_spend_stream_for_class(&group, ProofClass::B255).expect("B255 group");
        assert_eq!(facts.logical_count, 1);
        assert_eq!(facts.live_inputs, 1_020);
        assert_eq!(facts.live_outputs, 1);
    }
}
