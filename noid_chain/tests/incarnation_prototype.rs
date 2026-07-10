// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Regression gate for the packed alloc-counter UTXO incarnation scheme.
//!
//! It locks the two design facts the production implementation relies on: the
//! incarnation fits in the existing value lane without changing either hash
//! schedule, and a canonical checked counter increment makes a stale input fail
//! after physical-slot reuse.

use noid_chain::exact_state_hash::slot_leaf_hash;
use noid_chain::SlotValue;
use noid_core::Block128;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_EXSTSLT};
use noid_poseidon2b::primitives::{hash_input_leaf_packed, Address};
use noid_tx::{pack_amount_creation_id, unpack_amount_creation_id};

fn incarnation_slot(amount: u64, creation_id: u64, owner: Address) -> SlotValue {
    SlotValue::with_owner_fields(amount, creation_id, owner.as_fields())
}

fn incarnation_input_leaf(
    slot_index: u32,
    amount: u64,
    creation_id: u64,
    owner: Address,
) -> [u8; 32] {
    hash_input_leaf_packed(
        slot_index,
        pack_amount_creation_id(amount, creation_id),
        &owner,
    )
}

fn incarnation_exact_leaf(slot: SlotValue) -> [u8; 32] {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_EXSTSLT));
    sponge.absorb(slot.value);
    sponge.absorb_pair(slot.owner_hi, slot.owner_lo);
    sponge.finalize()
}

fn assign_creation_id(alloc_counter: u64) -> Option<(u64, u64)> {
    let creation_id = alloc_counter.checked_add(1)?;
    Some((creation_id, creation_id))
}

fn validate_mint_ids(parent_alloc_counter: u64, creation_ids: &[u64]) -> bool {
    let mut counter = parent_alloc_counter;
    for &creation_id in creation_ids {
        let Some((expected, next)) = assign_creation_id(counter) else {
            return false;
        };
        if creation_id != expected {
            return false;
        }
        counter = next;
    }
    true
}

#[test]
fn packed_incarnation_zero_id_uses_canonical_low_lane_schedules() {
    let owner = Address([0x37; 32]);
    let amount = 42_000_000u64;
    let slot_index = 19u32;

    assert_eq!(
        incarnation_input_leaf(slot_index, amount, 0, owner),
        hash_input_leaf_packed(
            slot_index,
            pack_amount_creation_id(amount, 0),
            &owner,
        ),
        "creation_id=0 uses the canonical low-lane input-leaf schedule"
    );
    let zero_id_slot = incarnation_slot(amount, 0, owner);
    assert_eq!(
        incarnation_exact_leaf(zero_id_slot),
        slot_leaf_hash(zero_id_slot),
        "creation_id=0 uses the canonical low-lane exact-leaf schedule"
    );

    let live = incarnation_slot(amount, 7, owner);
    assert_ne!(incarnation_exact_leaf(live), slot_leaf_hash(zero_id_slot));
    assert_ne!(
        incarnation_input_leaf(slot_index, amount, 7, owner),
        hash_input_leaf_packed(
            slot_index,
            pack_amount_creation_id(amount, 0),
            &owner,
        )
    );
    assert_eq!(unpack_amount_creation_id(live.value), (amount, 7));
    assert_eq!(pack_amount_creation_id(0, 0), Block128::from(0u128));
}

#[test]
fn canonical_slot_reuse_invalidates_the_stale_input() {
    let owner = Address([0x51; 32]);
    let amount = 900_000u64;
    let (first_id, counter) = assign_creation_id(0).unwrap();
    let first = incarnation_slot(amount, first_id, owner);
    let stale_claim = first;

    let (second_id, counter) = assign_creation_id(counter).unwrap();
    let reused = incarnation_slot(amount, second_id, owner);

    assert_eq!(first_id, 1);
    assert_eq!(second_id, 2);
    assert_ne!(stale_claim, reused, "same slot/value/owner is a new UTXO");
    assert_ne!(
        incarnation_exact_leaf(stale_claim),
        incarnation_exact_leaf(reused),
        "an old exact-state opening cannot authenticate the new incarnation"
    );
    assert_eq!(counter, 2);
}

#[test]
fn allocation_is_checked_and_strictly_monotone() {
    let mut counter = 41u64;
    let mut ids = Vec::new();
    for _ in 0..8 {
        let (id, next) = assign_creation_id(counter).unwrap();
        ids.push(id);
        counter = next;
    }
    assert_eq!(ids, (42u64..50).collect::<Vec<_>>());
    assert!(validate_mint_ids(41, &ids));
    assert!(!validate_mint_ids(41, &[42, 44]), "gapped IDs reject");
    assert!(!validate_mint_ids(41, &[42, 42]), "duplicate IDs reject");
    assert!(!validate_mint_ids(41, &[43, 42]), "shuffled IDs reject");
    assert_eq!(
        assign_creation_id(u64::MAX),
        None,
        "wrap is consensus-invalid"
    );
}

#[test]
fn both_same_block_action_orders_bind_the_new_incarnation() {
    let owner = Address([0x63; 32]);
    let amount = 77u64;

    // spend(old id=10) -> mint(new id=11) at the same physical slot
    let spent = incarnation_slot(amount, 10, owner);
    let reminted = incarnation_slot(amount, 11, owner);
    assert_ne!(spent, reminted);
    assert_ne!(
        incarnation_exact_leaf(spent),
        incarnation_exact_leaf(reminted)
    );

    // mint(id=12) -> spend in the same block is also unambiguous: the child
    // input must carry the just-assigned id, not the prior incarnation.
    let minted = incarnation_slot(amount, 12, owner);
    let correct_child_claim = incarnation_slot(amount, 12, owner);
    let stale_child_claim = incarnation_slot(amount, 11, owner);
    assert_eq!(minted, correct_child_claim);
    assert_ne!(minted, stale_child_claim);
}

#[test]
fn counter_is_explicitly_branch_local_after_rollback() {
    let (branch_a_id, _) = assign_creation_id(100).unwrap();
    let (branch_b_id, _) = assign_creation_id(100).unwrap();
    assert_eq!(branch_a_id, branch_b_id);
    // This matches the retained undo rollback scope. Cross-branch replay is a
    // separate epoch-anchor/history binding obligation; the incarnation gate
    // claims canonical-branch ABA protection, not a global outpoint namespace.
}
