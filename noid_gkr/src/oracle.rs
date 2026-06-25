// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Reference oracle: re-executes the 59-permutation spine slot-by-slot
//! using the native `noid_poseidon2b::Poseidon2bPermutation`. The
//! output is a full per-slot witness (`state_in`, `state_out`) plus
//! the final tx_body_hash as two field lanes.
//!
//! This is the ground-truth against which every later GKR prover stage
//! must byte-equal. If the spine ever diverges from
//! `noid_poseidon2b::primitives::hash_tx_body` on any fixture, we have
//! a protocol bug, not a benchmark discrepancy.

use noid_core::{Block128, CanonicalSerialize};
use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

use crate::circuit::{SlotDescriptor, SpineCircuit, SpineInputs};
use crate::tx_body_layout::InstanceRole;

/// Padding block pushed by a sponge `finalize()` when the absorb
/// buffer is empty: 32-byte `[0x80, 0, ..., 0, 0x01]` split into two
/// little-endian `u128` lanes. Matches
/// `noid_poseidon2b::native::compression::fill_padding` on an empty
/// buffer byte-for-byte.
#[inline]
fn padding_absorb_block() -> [Block128; 2] {
    let lo = Block128::from(0x80u128);
    // Last byte of the 16-byte slice, i.e. the high byte of the u128.
    let hi = Block128::from(0x01u128 << (15 * 8));
    [lo, hi]
}

/// Full per-slot state snapshot.
#[derive(Debug, Clone, Copy)]
pub struct SlotState {
    pub state_in: [Block128; 4],
    pub state_out: [Block128; 4],
}

impl SlotState {
    /// Digest produced by this slot's permutation: state_out[0..1].
    #[inline]
    pub fn digest(&self) -> [Block128; 2] {
        [self.state_out[0], self.state_out[1]]
    }
}

#[derive(Debug, Clone)]
pub struct SpineWitness {
    pub slots: Vec<SlotState>,
    /// Final `tx_body_hash` as two field lanes — this is the output
    /// canonical tx-body hash output cell.
    pub tx_body_hash: [Block128; 2],
}

impl SpineWitness {
    /// Re-encode the final hash as a 32-byte `Digest` matching
    /// `noid_poseidon2b::primitives::TxBodyHash`.
    pub fn tx_body_hash_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.tx_body_hash[0].to_bytes());
        out[16..].copy_from_slice(&self.tx_body_hash[1].to_bytes());
        out
    }
}

/// Drive the 59 permutations in post-order, producing the full witness.
/// This is the straight-line native witness builder and is not meant to be
/// fast.
pub fn evaluate_spine(circuit: &SpineCircuit, inputs: &SpineInputs) -> SpineWitness {
    let perm = Poseidon2bPermutation;
    let mut slots: Vec<SlotState> = Vec::with_capacity(circuit.slots.len());

    for slot in &circuit.slots {
        let state_in = build_state_in(slot, inputs, &slots);
        let mut state_out = state_in;
        perm.permute_mut(&mut state_out);
        slots.push(SlotState {
            state_in,
            state_out,
        });
    }

    let wrap = slots
        .last()
        .expect("spine must have at least the wrap slot");
    let tx_body_hash = wrap.digest();

    SpineWitness {
        slots,
        tx_body_hash,
    }
}

/// Build a slot's pre-MDS state from the layout + previous slots'
/// outputs + the transaction-wide boundary inputs.
fn build_state_in(
    slot: &SlotDescriptor,
    inputs: &SpineInputs,
    prev: &[SlotState],
) -> [Block128; 4] {
    let [iv_hi, iv_lo] = slot.capacity_iv;

    match slot.role {
        // -- Input-leaf sub-sponge (3 perms): hash_leaf([slot,value,owner_hi,owner_lo])
        InstanceRole::InputLeafPermA { leaf_idx } => {
            let payload = inputs.input_leaves[leaf_idx as usize];
            // state = [0,0,iv]; absorb_pair(payload[0], payload[1])
            [payload[0], payload[1], iv_hi, iv_lo]
        }
        InstanceRole::InputLeafPermB { leaf_idx } => {
            let payload = inputs.input_leaves[leaf_idx as usize];
            chain_absorb_pair(prev, slot, [payload[2], payload[3]])
        }
        InstanceRole::InputLeafPermC { .. } => {
            // Padding flush from an empty buffer: [0x80, 0x01<<120].
            chain_absorb_pair(prev, slot, padding_absorb_block())
        }

        // -- Output-leaf sub-sponge (2 perms): hash_output_leaf, no pad flush
        InstanceRole::OutputLeafPermA { leaf_idx } => {
            let payload = inputs.output_leaves[leaf_idx as usize];
            [payload[0], payload[1], iv_hi, iv_lo]
        }
        InstanceRole::OutputLeafPermB { leaf_idx } => {
            let payload = inputs.output_leaves[leaf_idx as usize];
            chain_absorb_pair(prev, slot, [payload[2], payload[3]])
        }

        // -- Compress sub-sponge (2 perms): compress(left, right) under TAG_COMPRESS
        InstanceRole::CompressPermA { level, pos } => {
            let left = resolve_child_digest(slot.left_child, prev, inputs, level, pos, true);
            [left[0], left[1], iv_hi, iv_lo]
        }
        InstanceRole::CompressPermB { level, pos } => {
            let right = resolve_child_digest(slot.right_child, prev, inputs, level, pos, false);
            chain_absorb_pair(prev, slot, right)
        }

        // -- Wrap sub-sponge (1 perm): state = [root[0], root[1], iv_txbody]
        InstanceRole::WrapPerm => {
            let root_id = slot
                .left_child
                .expect("wrap must reference a root spine instance");
            let root = prev[root_id].digest();
            [root[0], root[1], iv_hi, iv_lo]
        }
    }
}

/// Non-head chaining: take the previous slot's full post-permutation
/// state (same sub-sponge) and XOR the new absorb block into the rate
/// lanes.
#[inline]
fn chain_absorb_pair(
    prev: &[SlotState],
    slot: &SlotDescriptor,
    absorb: [Block128; 2],
) -> [Block128; 4] {
    let src = slot
        .prev_output_src
        .expect("non-head slot must carry prev_output_src");
    let s = prev[src].state_out;
    [s[0] + absorb[0], s[1] + absorb[1], s[2], s[3]]
}

/// Resolve a compress-node child digest. If the layout supplies a
/// spine instance id, use its output. Otherwise it is one of the four
/// non-AIR tree leaves (L0 / L1 / L14 / L15) and we pull it from
/// `SpineInputs`.
fn resolve_child_digest(
    child: Option<usize>,
    prev: &[SlotState],
    inputs: &SpineInputs,
    level: u8,
    pos: u8,
    is_left: bool,
) -> [Block128; 2] {
    if let Some(id) = child {
        return prev[id].digest();
    }

    // Only level-1 compress nodes can have non-AIR children in the
    // canonical layout (L0/L1 under pair 0; L14/L15 under pair 7).
    debug_assert_eq!(level, 1, "non-AIR child appeared outside level-1 compress");
    match (pos, is_left) {
        (0, true) => inputs.epoch_anchor,
        (0, false) => inputs.fee_leaf,
        (7, true) => inputs.is_coinbase_leaf,
        (7, false) => inputs.pad_leaf,
        _ => panic!("unexpected non-AIR child at compress (level={level}, pos={pos})"),
    }
}

/// Translate a 32-byte native digest into two field lanes the same
/// way `Digest::as_fields` does in `noid_poseidon2b::primitives`.
pub fn digest_to_fields(d: &[u8; 32]) -> [Block128; 2] {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&d[..16]);
    b.copy_from_slice(&d[16..]);
    [
        Block128::from(u128::from_le_bytes(a)),
        Block128::from(u128::from_le_bytes(b)),
    ]
}
