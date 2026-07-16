// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Minimal same-builder binding from authenticated Tx8x2 spine aliases to the
//! P128 logical scanner and action surface.

use noid_core::Block128;
use noid_poseidon2b::primitives::Address;
use noid_recursive::acceptance::trace::action_surface::ActionRowTrace;
use noid_recursive::acceptance::trace::public_arithmetic::{
    split_packed_input_value, PackedInputValueTrace,
};
use noid_recursive::acceptance::trace::tx_body_spine::{SpineInputsTrace, TX_BODY_RAW_LEAVES};
use noid_tx::{TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

use crate::circuit_support::{
    alloc_block, const_block, mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr,
    F128,
};
use crate::paged_spend_relation::{
    bind_paged_spend_block_reusing_ranges, PagedSpendBlockTrace, PagedSpendPageProvenRanges,
    PagedSpendPageTraceInput, ProvenU64Range, PAGED_SPEND_AUTH_CAPACITY, PAGED_SPEND_PAGE_CAPACITY,
};

use noid_tx::body_hash::{
    TX8X2_LEAF_EPOCH_ANCHOR as LEAF_EPOCH_ANCHOR, TX8X2_LEAF_FEE as LEAF_FEE,
    TX8X2_LEAF_FLAGS as LEAF_FLAGS, TX8X2_LEAF_INPUT_BASE as LEAF_INPUT_BASE,
    TX8X2_LEAF_INPUT_OWNER as LEAF_INPUT_OWNER, TX8X2_LEAF_OUTPUT0_DATA as LEAF_OUTPUT0_DATA,
};

const ACTION_BITS: usize = TX_INPUTS + TX_OUTPUTS;
const START_INDEX: usize = ACTION_BITS;
const END_INDEX: usize = START_INDEX + 1;
const PAGED_VALIDITY_BITS: usize = END_INDEX + 1;
const U64_BITS: usize = 64;

/// Measured adapter delta after spine, hash, and page-liveness aliases exist.
/// Includes canonical padding, action surfaces, packed input splits, all u64
/// ranges, declared counts, and the range-reusing logical scanner.
pub const P128_PAGE_BINDING_ROWS: usize = 656_961;

const _: () = assert!(PAGED_VALIDITY_BITS == 12);
const _: () = assert!(1u16 << START_INDEX == crate::paged_spend::PAGEDSPEND_START_BIT);
const _: () = assert!(1u16 << END_INDEX == crate::paged_spend::PAGEDSPEND_END_BIT);

pub struct BoundPageActions {
    pub start: LinExpr,
    pub end: LinExpr,
    pub raw_inputs: [LinExpr; TX_INPUTS],
    pub raw_outputs: [LinExpr; TX_OUTPUTS],
    pub input_rows: [ActionRowTrace; TX_INPUTS],
    pub output_rows: [ActionRowTrace; TX_OUTPUTS],
}

impl BoundPageActions {
    pub fn ordered_rows(&self) -> impl Iterator<Item = ActionRowTrace> + '_ {
        self.input_rows
            .iter()
            .chain(self.output_rows.iter())
            .cloned()
    }
}

pub struct P128PageBinding {
    pub actions: Vec<BoundPageActions>,
    pub scanner: PagedSpendBlockTrace<PAGED_SPEND_AUTH_CAPACITY>,
    pub declared_page_counts: Vec<LinExpr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageBindingError {
    SpineCount { actual: usize },
    HashCount { actual: usize },
    LivenessCount { actual: usize },
    HintCount { actual: usize },
}

fn canonical_padding_body() -> TxBody {
    TxBody {
        epoch_anchor: [0u8; 32],
        fee: 0,
        input_owner: Address([0u8; 32]),
        inputs: [TxInput::dummy(); TX_INPUTS],
        outputs: [TxOutput::dummy(); TX_OUTPUTS],
        validity_bitmap: 0,
        is_coinbase: false,
    }
}

fn bind_dead_pair(builder: &mut FieldR1csBuilder, live: &LinExpr, pair: &[LinExpr; 2]) {
    let dead = live.add_const(F128::ONE);
    for lane in pair {
        let product = mul(builder, &dead, lane);
        pin_zero(builder, &product);
    }
}

fn selected_row(
    builder: &mut FieldR1csBuilder,
    live: &LinExpr,
    data: &[LinExpr; 2],
    owner: &[LinExpr; 2],
    is_mint: bool,
) -> ActionRowTrace {
    ActionRowTrace {
        live: live.clone(),
        slot_index: mul(builder, live, &data[0]),
        value: mul(builder, live, &data[1]),
        owner: std::array::from_fn(|lane| mul(builder, live, &owner[lane])),
        is_mint: if is_mint {
            live.clone()
        } else {
            LinExpr::zero()
        },
    }
}

fn prove_u64(builder: &mut FieldR1csBuilder, value: &LinExpr) -> ProvenU64Range {
    ProvenU64Range {
        value: value.clone(),
        bits: range_check_bits(builder, value, U64_BITS)
            .try_into()
            .expect("u64 range has exactly 64 bits"),
    }
}

fn bind_canonical_padding(
    builder: &mut FieldR1csBuilder,
    page_live: &LinExpr,
    spine: &SpineInputsTrace,
    page_hash: &[LinExpr; 2],
    canonical_leaves: &[[Block128; 2]; TX_BODY_RAW_LEAVES],
    canonical_hash: &[Block128; 2],
) {
    let dead = page_live.add_const(F128::ONE);
    for (actual, canonical) in spine.leaves.iter().zip(canonical_leaves) {
        for lane in 0..2 {
            let difference = actual[lane].add(&const_block(canonical[lane]));
            let product = mul(builder, &dead, &difference);
            pin_zero(builder, &product);
        }
    }
    for lane in 0..2 {
        let difference = page_hash[lane].add(&const_block(canonical_hash[lane]));
        let product = mul(builder, &dead, &difference);
        pin_zero(builder, &product);
    }
}

fn bind_page(
    builder: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    page_hash: &[LinExpr; 2],
    page_live: &LinExpr,
    declared_page_count: LinExpr,
) -> (
    BoundPageActions,
    PagedSpendPageTraceInput,
    PagedSpendPageProvenRanges,
) {
    let live_square = mul(builder, page_live, page_live);
    pin_eq(builder, &live_square, page_live);

    let flag_bits = range_check_bits(builder, &spine.leaves[LEAF_FLAGS][0], PAGED_VALIDITY_BITS);
    pin_zero(builder, &spine.leaves[LEAF_FLAGS][1]);
    let raw_inputs = std::array::from_fn(|slot| LinExpr::from_wire(flag_bits[slot]));
    let raw_outputs = std::array::from_fn(|slot| LinExpr::from_wire(flag_bits[TX_INPUTS + slot]));
    let start = LinExpr::from_wire(flag_bits[START_INDEX]);
    let end = LinExpr::from_wire(flag_bits[END_INDEX]);

    for (slot, selector) in raw_inputs.iter().enumerate() {
        bind_dead_pair(builder, selector, &spine.leaves[LEAF_INPUT_BASE + slot]);
    }
    for (slot, selector) in raw_outputs.iter().enumerate() {
        let data_leaf = LEAF_OUTPUT0_DATA + 2 * slot;
        bind_dead_pair(builder, selector, &spine.leaves[data_leaf]);
        bind_dead_pair(builder, selector, &spine.leaves[data_leaf + 1]);
    }

    let selected_inputs: [LinExpr; TX_INPUTS] =
        std::array::from_fn(|slot| mul(builder, page_live, &raw_inputs[slot]));
    let selected_outputs: [LinExpr; TX_OUTPUTS] =
        std::array::from_fn(|slot| mul(builder, page_live, &raw_outputs[slot]));
    let input_rows = std::array::from_fn(|slot| {
        selected_row(
            builder,
            &selected_inputs[slot],
            &spine.leaves[LEAF_INPUT_BASE + slot],
            &spine.leaves[LEAF_INPUT_OWNER],
            false,
        )
    });
    let output_rows = std::array::from_fn(|slot| {
        let data_leaf = LEAF_OUTPUT0_DATA + 2 * slot;
        selected_row(
            builder,
            &selected_outputs[slot],
            &spine.leaves[data_leaf],
            &spine.leaves[data_leaf + 1],
            true,
        )
    });

    let packed_inputs: [PackedInputValueTrace; TX_INPUTS] = std::array::from_fn(|slot| {
        split_packed_input_value(builder, &spine.leaves[LEAF_INPUT_BASE + slot][1])
    });
    let input_amounts = std::array::from_fn(|slot| packed_inputs[slot].amount.value.clone());
    let input_ranges = std::array::from_fn(|slot| ProvenU64Range {
        value: packed_inputs[slot].amount.value.clone(),
        bits: packed_inputs[slot].amount.bits,
    });
    let output_amounts =
        std::array::from_fn(|slot| spine.leaves[LEAF_OUTPUT0_DATA + 2 * slot][1].clone());
    let output_ranges = std::array::from_fn(|slot| prove_u64(builder, &output_amounts[slot]));
    let fee = spine.leaves[LEAF_FEE][0].clone();
    let fee_range = prove_u64(builder, &fee);
    pin_zero(builder, &spine.leaves[LEAF_FEE][1]);

    let actions = BoundPageActions {
        start: start.clone(),
        end: end.clone(),
        raw_inputs: raw_inputs.clone(),
        raw_outputs: raw_outputs.clone(),
        input_rows,
        output_rows,
    };
    let scanner_input = PagedSpendPageTraceInput {
        page_live: page_live.clone(),
        start,
        end,
        declared_page_count,
        page_hash: page_hash.clone(),
        input_owner: spine.leaves[LEAF_INPUT_OWNER].clone(),
        epoch_anchor: spine.leaves[LEAF_EPOCH_ANCHOR].clone(),
        fee,
        input_live: raw_inputs,
        input_amounts,
        output_live: raw_outputs,
        output_amounts,
    };
    let ranges = PagedSpendPageProvenRanges {
        fee: fee_range,
        inputs: input_ranges,
        outputs: output_ranges,
    };
    (actions, scanner_input, ranges)
}

/// Bind exactly 128 page spines. The caller-owned spine/hash aliases are an
/// explicit authenticated-interface placeholder; their verifier rows are not
/// included in this adapter delta.
pub fn bind_p128_pages_from_spine_aliases(
    builder: &mut FieldR1csBuilder,
    spines: &[SpineInputsTrace],
    page_hashes: &[[LinExpr; 2]],
    page_live: &[LinExpr],
    declared_page_count_hints: &[u16],
) -> Result<P128PageBinding, PageBindingError> {
    let before = builder.num_wires();
    for (actual, error) in [
        (
            spines.len(),
            PageBindingError::SpineCount {
                actual: spines.len(),
            },
        ),
        (
            page_hashes.len(),
            PageBindingError::HashCount {
                actual: page_hashes.len(),
            },
        ),
        (
            page_live.len(),
            PageBindingError::LivenessCount {
                actual: page_live.len(),
            },
        ),
        (
            declared_page_count_hints.len(),
            PageBindingError::HintCount {
                actual: declared_page_count_hints.len(),
            },
        ),
    ] {
        if actual != PAGED_SPEND_PAGE_CAPACITY {
            return Err(error);
        }
    }

    let padding = canonical_padding_body();
    let padding_leaves = noid_tx::body_hash::body_hash_leaves(&padding);
    let padding_hash = padding.txid().as_fields();
    let mut actions = Vec::with_capacity(PAGED_SPEND_PAGE_CAPACITY);
    let mut scanner_inputs = Vec::with_capacity(PAGED_SPEND_PAGE_CAPACITY);
    let mut ranges = Vec::with_capacity(PAGED_SPEND_PAGE_CAPACITY);
    let mut declared_page_counts = Vec::with_capacity(PAGED_SPEND_PAGE_CAPACITY);

    for page in 0..PAGED_SPEND_PAGE_CAPACITY {
        bind_canonical_padding(
            builder,
            &page_live[page],
            &spines[page],
            &page_hashes[page],
            &padding_leaves,
            &padding_hash,
        );
        let declared = alloc_block(
            builder,
            Block128::from(declared_page_count_hints[page] as u128),
        );
        let (page_actions, scanner_input, page_ranges) = bind_page(
            builder,
            &spines[page],
            &page_hashes[page],
            &page_live[page],
            declared.clone(),
        );
        actions.push(page_actions);
        scanner_inputs.push(scanner_input);
        ranges.push(page_ranges);
        declared_page_counts.push(declared);
    }

    let scanner_inputs: [PagedSpendPageTraceInput; PAGED_SPEND_PAGE_CAPACITY] = scanner_inputs
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed P128 loop"));
    let scanner = bind_paged_spend_block_reusing_ranges(builder, &scanner_inputs, &ranges);
    let binding = P128PageBinding {
        actions,
        scanner,
        declared_page_counts,
    };
    assert_eq!(
        builder.num_wires() - before,
        P128_PAGE_BINDING_ROWS,
        "minimal P128 page binding row drift"
    );
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paged_spend::{
        validate_paged_spend_stream, TxPage, PAGEDSPEND_END_BIT, PAGEDSPEND_START_BIT,
    };
    use noid_gkr::spine_statement::spine_inputs_from_body;
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxInput, TxOutput};

    const INPUT_AMOUNT: u64 = 100_000;

    fn owner(seed: u32) -> Address {
        let mut bytes = [0x42u8; 32];
        bytes[..4].copy_from_slice(&seed.to_le_bytes());
        Address(bytes)
    }

    fn group(seed: u32, input_count: usize, output_count: usize, fee: u64) -> Vec<TxPage> {
        let page_count = input_count
            .div_ceil(TX_INPUTS)
            .max(output_count.div_ceil(TX_OUTPUTS))
            .max(1);
        let output_total = input_count as u64 * INPUT_AMOUNT - fee;
        (0..page_count)
            .map(|page| {
                let mut inputs = [TxInput::dummy(); TX_INPUTS];
                let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
                let mut bitmap = 0u16;
                for slot in 0..TX_INPUTS {
                    let index = page * TX_INPUTS + slot;
                    if index < input_count {
                        inputs[slot] = TxInput {
                            slot_index: seed * 2_000 + index as u32 + 1,
                            amount: INPUT_AMOUNT,
                            creation_id: u64::from(seed) * 2_000 + index as u64 + 50,
                        };
                        bitmap |= 1 << slot;
                    }
                }
                for slot in 0..TX_OUTPUTS {
                    let index = page * TX_OUTPUTS + slot;
                    if index < output_count {
                        outputs[slot] = TxOutput {
                            slot_index: 1_000_000 + seed * 300 + index as u32,
                            amount: if index + 1 == output_count {
                                output_total - (output_count as u64 - 1)
                            } else {
                                1
                            },
                            owner: owner(seed.wrapping_add(10_000)),
                        };
                        bitmap |= output_bitmap_bit(slot);
                    }
                }
                if page == 0 {
                    bitmap |= PAGEDSPEND_START_BIT;
                }
                if page + 1 == page_count {
                    bitmap |= PAGEDSPEND_END_BIT;
                }
                TxPage::new(TxBody {
                    epoch_anchor: [seed as u8; 32],
                    fee: if page == 0 { fee } else { 0 },
                    input_owner: owner(seed),
                    inputs,
                    outputs,
                    validity_bitmap: bitmap,
                    is_coinbase: false,
                })
                .unwrap()
            })
            .collect()
    }

    struct BuiltCase {
        adapter_rows: usize,
        useful_rows: usize,
        matrix: Option<FieldR1cs>,
        witness: Vec<F128>,
    }

    fn build_case(groups: &[Vec<TxPage>], record_matrix: bool) -> BuiltCase {
        let pages = groups.iter().flatten().cloned().collect::<Vec<_>>();
        validate_paged_spend_stream(&pages).unwrap();
        let padding = canonical_padding_body();
        let bodies = pages
            .iter()
            .map(|page| page.body.clone())
            .chain(std::iter::repeat(padding))
            .take(PAGED_SPEND_PAGE_CAPACITY)
            .collect::<Vec<_>>();
        let mut hints = vec![0u16; PAGED_SPEND_PAGE_CAPACITY];
        let mut cursor = 0usize;
        for group in groups {
            hints[cursor] = group.len() as u16;
            cursor += group.len();
        }

        let mut builder = if record_matrix {
            FieldR1csBuilder::new()
        } else {
            FieldR1csBuilder::new_witness_only()
        };
        let spines = bodies
            .iter()
            .map(spine_inputs_from_body)
            .map(|native| SpineInputsTrace::alloc(&mut builder, &native))
            .collect::<Vec<_>>();
        let hashes = bodies
            .iter()
            .map(|body| {
                body.txid()
                    .as_fields()
                    .map(|lane| alloc_block(&mut builder, lane))
            })
            .collect::<Vec<_>>();
        let live = (0..PAGED_SPEND_PAGE_CAPACITY)
            .map(|page| alloc_block(&mut builder, Block128::from((page < pages.len()) as u128)))
            .collect::<Vec<_>>();
        let before = builder.num_wires();
        let binding =
            bind_p128_pages_from_spine_aliases(&mut builder, &spines, &hashes, &live, &hints)
                .unwrap();
        assert_eq!(binding.actions.len(), PAGED_SPEND_PAGE_CAPACITY);
        assert_eq!(
            binding
                .actions
                .iter()
                .map(|page| page.ordered_rows().count())
                .sum::<usize>(),
            PAGED_SPEND_PAGE_CAPACITY * noid_tx::TX_ACTIONS,
        );
        let adapter_rows = builder.num_wires() - before;
        assert_eq!(adapter_rows, P128_PAGE_BINDING_ROWS);
        if record_matrix {
            let (matrix, witness) = builder.build();
            BuiltCase {
                adapter_rows,
                useful_rows: matrix.useful_rows,
                matrix: Some(matrix),
                witness,
            }
        } else {
            let (useful_rows, witness) = builder.build_witness_only();
            BuiltCase {
                adapter_rows,
                useful_rows,
                matrix: None,
                witness,
            }
        }
    }

    #[test]
    fn minimal_p128_page_binding_census_is_content_fixed() {
        let mut baseline = build_case(&[group(1, 100, 1, 15_700)], true);
        let matrix = baseline.matrix.take().unwrap();
        assert_eq!(baseline.adapter_rows, P128_PAGE_BINDING_ROWS);
        assert!(matrix.satisfies(&baseline.witness));

        let maximum = build_case(&[group(2, 1_020, 1, 5_000)], false);
        let independent = build_case(
            &(0..PAGED_SPEND_AUTH_CAPACITY)
                .map(|index| group(10_000 + index as u32, 1, 1, 3))
                .collect::<Vec<_>>(),
            false,
        );
        for case in [maximum, independent] {
            assert_eq!(case.adapter_rows, P128_PAGE_BINDING_ROWS);
            assert_eq!(case.useful_rows, baseline.useful_rows);
            assert!(matrix.satisfies(&case.witness));
        }
    }
}
