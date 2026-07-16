// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! One-builder non-authorization core assembled from measured P128 pieces.
//!
//! This closes the most important local seams: the coinbase amount range is
//! shared by its action and reward ceiling, scanner END aliases feed logical
//! fees directly, and page actions plus coinbase enter one Beneš relation.
//! Authenticated spine/root carriers, exact state, parent recursion and public
//! IO are still explicit missing components; this is therefore a partial
//! census, never a complete-m23 claim.

use noid_recursive::acceptance::trace::action_compaction::CompactedActionTrace;
use noid_recursive::acceptance::trace::action_surface::{
    bind_coinbase_action_with_amount, CoinbaseActionTrace,
};
use noid_recursive::acceptance::trace::exact_state::StateDepthTrace;
use noid_recursive::acceptance::trace::tx_body_spine::SpineInputsTrace;

use crate::action_relation::{bind_p128_action_relation, ACTION_CANDIDATES};
use crate::circuit_support::{pin_eq, FieldR1csBuilder, LinExpr};
use crate::group_fee::{bind_p128_group_fee_arithmetic, P128BlockFeeTrace, P128_GROUP_FEE_ROWS};
use crate::page_binding::{
    bind_p128_pages_from_spine_aliases, P128PageBinding, PageBindingError, P128_PAGE_BINDING_ROWS,
};

/// Coinbase semantic surface plus its binding to the header miner address.
pub const P128_COINBASE_BINDING_ROWS: usize = 137;
/// Exact one-builder delta of all currently closed non-authorization pieces.
pub const P128_PARTIAL_NONAUTH_ROWS: usize = P128_COINBASE_BINDING_ROWS
    + P128_PAGE_BINDING_ROWS
    + P128_GROUP_FEE_ROWS
    + crate::action_relation::ACTION_RELATION_ROWS;

const _: () = assert!(P128_PARTIAL_NONAUTH_ROWS == 1_139_062);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialNonAuthorizationLedger {
    pub coinbase_binding: usize,
    pub page_binding_and_scanner: usize,
    pub group_fee_and_reward: usize,
    pub action_relation: usize,
    pub total: usize,
}

impl PartialNonAuthorizationLedger {
    pub const EXPECTED: Self = Self {
        coinbase_binding: P128_COINBASE_BINDING_ROWS,
        page_binding_and_scanner: P128_PAGE_BINDING_ROWS,
        group_fee_and_reward: P128_GROUP_FEE_ROWS,
        action_relation: crate::action_relation::ACTION_RELATION_ROWS,
        total: P128_PARTIAL_NONAUTH_ROWS,
    };
}

pub struct P128PartialNonAuthorizationTrace {
    pub coinbase: CoinbaseActionTrace,
    pub pages: P128PageBinding,
    pub fees: P128BlockFeeTrace,
    pub compacted_actions: CompactedActionTrace,
    pub ledger: PartialNonAuthorizationLedger,
}

/// Assemble the closed P128 non-authorization core in one builder.
///
/// The supplied spine/hash aliases are intentionally not authenticated here;
/// their carrier/verifier cost belongs to the still-open complete census.
#[allow(clippy::too_many_arguments)]
pub fn bind_p128_partial_nonauthorization(
    builder: &mut FieldR1csBuilder,
    coinbase_spine: &SpineInputsTrace,
    miner: &[LinExpr; 2],
    page_spines: &[SpineInputsTrace],
    page_hashes: &[[LinExpr; 2]],
    page_live: &[LinExpr],
    declared_page_count_hints: &[u16],
    parent_active_count: &LinExpr,
    parent_depth: &StateDepthTrace,
    child_depth: &StateDepthTrace,
    parent_alloc_counter: &LinExpr,
    child_alloc_counter: &LinExpr,
    block_height: &LinExpr,
) -> Result<P128PartialNonAuthorizationTrace, PageBindingError> {
    let total_before = builder.num_wires();

    let before = builder.num_wires();
    let coinbase = bind_coinbase_action_with_amount(builder, coinbase_spine);
    for lane in 0..2 {
        pin_eq(builder, &coinbase.action.owner[lane], &miner[lane]);
    }
    let coinbase_binding = builder.num_wires() - before;
    assert_eq!(coinbase_binding, P128_COINBASE_BINDING_ROWS);

    let before = builder.num_wires();
    let pages = bind_p128_pages_from_spine_aliases(
        builder,
        page_spines,
        page_hashes,
        page_live,
        declared_page_count_hints,
    )?;
    let page_binding_and_scanner = builder.num_wires() - before;
    assert_eq!(page_binding_and_scanner, P128_PAGE_BINDING_ROWS);

    let before = builder.num_wires();
    let fees = bind_p128_group_fee_arithmetic(
        builder,
        &pages.scanner.end_rows,
        parent_active_count,
        parent_depth,
        child_depth,
        &coinbase.amount,
        &coinbase.amount_bits,
    );
    let group_fee_and_reward = builder.num_wires() - before;
    assert_eq!(group_fee_and_reward, P128_GROUP_FEE_ROWS);

    let mut candidates = Vec::with_capacity(ACTION_CANDIDATES);
    candidates.push(coinbase.action.clone());
    candidates.extend(pages.actions.iter().flat_map(|page| page.ordered_rows()));
    assert_eq!(candidates.len(), ACTION_CANDIDATES);
    let before = builder.num_wires();
    let compacted_actions = bind_p128_action_relation(
        builder,
        &mut candidates,
        parent_alloc_counter,
        child_alloc_counter,
        block_height,
    );
    let action_relation = builder.num_wires() - before;

    let ledger = PartialNonAuthorizationLedger {
        coinbase_binding,
        page_binding_and_scanner,
        group_fee_and_reward,
        action_relation,
        total: builder.num_wires() - total_before,
    };
    assert_eq!(ledger, PartialNonAuthorizationLedger::EXPECTED);

    Ok(P128PartialNonAuthorizationTrace {
        coinbase,
        pages,
        fees,
        compacted_actions,
        ledger,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::{hardware::flat_to_tower_u128, Block128};
    use noid_gkr::spine_statement::spine_inputs_from_body;
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    use crate::circuit_support::{alloc_block, F128};
    use crate::geometry::{INPUT_CAPACITY, OUTPUT_CAPACITY, PAGE_CAPACITY};
    use crate::paged_spend::{
        validate_paged_spend_stream, TxPage, PAGEDSPEND_END_BIT, PAGEDSPEND_START_BIT,
    };

    const INPUT_AMOUNT: u64 = 100_000;
    const PARENT_ALLOC_COUNTER: u64 = 50_000_000;
    const COINBASE_SLOT: u32 = 4_000_000_000;

    fn owner(seed: u32) -> Address {
        let mut bytes = [0x42u8; 32];
        bytes[..4].copy_from_slice(&seed.to_le_bytes());
        Address(bytes)
    }

    fn group(
        seed: u32,
        input_count: usize,
        output_count: usize,
        active: u64,
        depth: u32,
        tip: u64,
    ) -> Vec<TxPage> {
        assert!((1..=INPUT_CAPACITY).contains(&input_count));
        assert!((1..=OUTPUT_CAPACITY).contains(&output_count));
        let fee = noid_chain::consensus::fees::fee_breakdown(
            input_count as u64,
            output_count as u64,
            active,
            depth,
        )
        .required_total
        .checked_add(tip)
        .unwrap();
        let page_count = input_count
            .div_ceil(TX_INPUTS)
            .max(output_count.div_ceil(TX_OUTPUTS));
        let output_total = (input_count as u64)
            .checked_mul(INPUT_AMOUNT)
            .and_then(|sum| sum.checked_sub(fee))
            .expect("fixture funds its fee");
        let input_base = seed.checked_mul(2_048).unwrap();
        let output_base = 1_000_000_000u32
            .checked_add(seed.checked_mul(512).unwrap())
            .unwrap();

        (0..page_count)
            .map(|page| {
                let mut inputs = [TxInput::dummy(); TX_INPUTS];
                let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
                let mut bitmap = 0u16;
                for slot in 0..TX_INPUTS {
                    let index = page * TX_INPUTS + slot;
                    if index < input_count {
                        inputs[slot] = TxInput {
                            slot_index: input_base + index as u32 + 1,
                            amount: INPUT_AMOUNT,
                            creation_id: u64::from(input_base) + index as u64 + 50,
                        };
                        bitmap |= 1 << slot;
                    }
                }
                for slot in 0..TX_OUTPUTS {
                    let index = page * TX_OUTPUTS + slot;
                    if index < output_count {
                        outputs[slot] = TxOutput {
                            slot_index: output_base + index as u32,
                            amount: if index + 1 == output_count {
                                output_total - (output_count as u64 - 1)
                            } else {
                                1
                            },
                            owner: owner(seed.wrapping_add(1_000_000)),
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

    fn maximum_coinbase(groups: &[Vec<TxPage>], active: u64, depth: u32) -> u64 {
        let claimable = groups
            .iter()
            .map(|group| {
                let inputs = group
                    .iter()
                    .map(|page| page.body.live_input_count())
                    .sum::<usize>();
                let outputs = group
                    .iter()
                    .map(|page| page.body.live_output_count())
                    .sum::<usize>();
                let breakdown = noid_chain::consensus::fees::fee_breakdown(
                    inputs as u64,
                    outputs as u64,
                    active,
                    depth,
                );
                u128::from(group[0].body.fee - breakdown.burned)
            })
            .sum::<u128>();
        u64::try_from(u128::from(noid_chain::consensus::emission::block_reward(depth)) + claimable)
            .unwrap()
    }

    fn coinbase_body(amount: u64) -> TxBody {
        let miner = owner(0x00c0_1aba);
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: COINBASE_SLOT,
            amount,
            owner: miner,
        };
        TxBody {
            epoch_anchor: [0x62; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        }
    }

    struct BuiltCase {
        matrix: Option<FieldR1cs>,
        witness: Vec<F128>,
        useful_rows: usize,
        partial_rows: usize,
        trace: P128PartialNonAuthorizationTrace,
    }

    fn value(witness: &[F128], expression: &LinExpr) -> u128 {
        let flat = expression.eval(witness);
        flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64))
    }

    fn build_case(
        groups: &[Vec<TxPage>],
        active: u64,
        depth: u32,
        record_matrix: bool,
    ) -> BuiltCase {
        let pages = groups.iter().flatten().cloned().collect::<Vec<_>>();
        assert!(pages.len() <= PAGE_CAPACITY);
        validate_paged_spend_stream(&pages).unwrap();
        let coinbase = coinbase_body(maximum_coinbase(groups, active, depth));
        let padding = TxBody {
            epoch_anchor: [0u8; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [TxOutput::dummy(); TX_OUTPUTS],
            validity_bitmap: 0,
            is_coinbase: false,
        };
        let page_bodies = pages
            .iter()
            .map(|page| page.body.clone())
            .chain(std::iter::repeat(padding))
            .take(PAGE_CAPACITY)
            .collect::<Vec<_>>();
        let mut hints = vec![0u16; PAGE_CAPACITY];
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
        let coinbase_spine =
            SpineInputsTrace::alloc(&mut builder, &spine_inputs_from_body(&coinbase));
        let page_spines = page_bodies
            .iter()
            .map(spine_inputs_from_body)
            .map(|native| SpineInputsTrace::alloc(&mut builder, &native))
            .collect::<Vec<_>>();
        let page_hashes = page_bodies
            .iter()
            .map(|body| {
                body.txid()
                    .as_fields()
                    .map(|lane| alloc_block(&mut builder, lane))
            })
            .collect::<Vec<_>>();
        let page_live = (0..PAGE_CAPACITY)
            .map(|page| alloc_block(&mut builder, Block128::from((page < pages.len()) as u128)))
            .collect::<Vec<_>>();
        let miner_native = coinbase.outputs[0].owner.as_fields();
        let miner = miner_native.map(|lane| alloc_block(&mut builder, lane));
        let parent_active = alloc_block(&mut builder, Block128::from(active as u128));
        let parent_depth_value = alloc_block(&mut builder, Block128::from(depth as u128));
        let child_depth_value = alloc_block(&mut builder, Block128::from(depth as u128));
        let parent_depth = StateDepthTrace::bind(&mut builder, &parent_depth_value);
        let child_depth = StateDepthTrace::bind(&mut builder, &child_depth_value);
        let live_outputs = groups
            .iter()
            .flatten()
            .map(|page| page.body.live_output_count())
            .sum::<usize>();
        let parent_alloc = alloc_block(&mut builder, Block128::from(PARENT_ALLOC_COUNTER as u128));
        let child_alloc = alloc_block(
            &mut builder,
            Block128::from((PARENT_ALLOC_COUNTER + 1 + live_outputs as u64) as u128),
        );
        let height = alloc_block(&mut builder, Block128::from(7u128));

        let before = builder.num_wires();
        let trace = bind_p128_partial_nonauthorization(
            &mut builder,
            &coinbase_spine,
            &miner,
            &page_spines,
            &page_hashes,
            &page_live,
            &hints,
            &parent_active,
            &parent_depth,
            &child_depth,
            &parent_alloc,
            &child_alloc,
            &height,
        )
        .unwrap();
        let partial_rows = builder.num_wires() - before;
        if record_matrix {
            let (matrix, witness) = builder.build();
            BuiltCase {
                useful_rows: matrix.useful_rows,
                matrix: Some(matrix),
                witness,
                partial_rows,
                trace,
            }
        } else {
            let (useful_rows, witness) = builder.build_witness_only();
            BuiltCase {
                matrix: None,
                witness,
                useful_rows,
                partial_rows,
                trace,
            }
        }
    }

    fn on_relation_stack(test: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .name("p128-partial-relation".into())
            .stack_size(64 * 1024 * 1024)
            .spawn(test)
            .expect("spawn P128 relation test")
            .join()
            .expect("P128 relation test panicked");
    }

    #[test]
    fn real_scanner_aliases_feed_fee_and_action_relations() {
        on_relation_stack(|| {
            let active = 0;
            let depth = 24;
            let groups = [group(1, 100, 13, active, depth, 11)];
            let case = build_case(&groups, active, depth, true);
            let matrix = case.matrix.as_ref().unwrap();
            assert!(matrix.satisfies(&case.witness));
            assert_eq!(case.partial_rows, P128_PARTIAL_NONAUTH_ROWS);
            assert_eq!(case.trace.ledger, PartialNonAuthorizationLedger::EXPECTED);
            assert_eq!(case.trace.pages.scanner.end_rows.len(), PAGE_CAPACITY);
            assert_eq!(case.trace.fees.groups.len(), PAGE_CAPACITY);
            assert_eq!(case.trace.compacted_actions.source_rows, ACTION_CANDIDATES);
            assert_eq!(
                value(&case.witness, &case.trace.fees.groups[12].live_input_count),
                100
            );
        });
    }

    #[test]
    fn integrated_partial_matrix_is_fixed_for_sweep_and_128_tps_shape() {
        on_relation_stack(|| {
            let active = 0;
            let depth = 24;
            let mut baseline = build_case(&[group(2, 1, 1, active, depth, 0)], active, depth, true);
            let matrix = baseline.matrix.take().unwrap();
            assert!(matrix.satisfies(&baseline.witness));

            let saturated_actions = build_case(
                &[group(3, INPUT_CAPACITY, OUTPUT_CAPACITY, active, depth, 13)],
                active,
                depth,
                false,
            );
            let independent = build_case(
                &(0..crate::geometry::AUTHORIZATION_CAPACITY)
                    .map(|index| group(10_000 + index as u32, 1, 1, active, depth, 3))
                    .collect::<Vec<_>>(),
                active,
                depth,
                false,
            );
            for case in [saturated_actions, independent] {
                assert_eq!(case.partial_rows, P128_PARTIAL_NONAUTH_ROWS);
                assert_eq!(case.useful_rows, baseline.useful_rows);
                assert_eq!(case.trace.ledger, PartialNonAuthorizationLedger::EXPECTED);
                assert!(matrix.satisfies(&case.witness));
            }
        });
    }
}
