// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Claims commitment (C_claimed): a Poseidon2b sponge binding the
//! claimed transaction slot values to canonical TxLogic public inputs. The
//! block-level exact transition proof authenticates the same slots and values.

use noid_core::Block128;
use noid_poseidon2b::native::{
    compression::Poseidon2bSponge,
    domain::{capacity_iv, TAG_CLAIMS},
};
use noid_poseidon2b::primitives::Digest;

use crate::types::{pack_amount_creation_id, TxInput, TxOutput};

/// Compute the binding commitment to all claimed slot values.
///
/// Absorbs `(slot_index, pack(value, creation_id), owner_hi, owner_lo)` for each input
/// followed by each output into a Poseidon2b sponge under `TAG_CLAIMS`.
/// Only live (valid=true) entries are included; dummy entries are skipped
/// to minimize hashing cost without affecting security (the count of
/// live entries is separately bound in PublicInputs).
///
/// The resulting digest is absorbed into canonical TxLogic public inputs,
/// cryptographically binding the block-side exact transition proof to these
/// slot claims. Any change to a claimed slot value changes the digest.
pub fn compute_claims_commitment(inputs: &[TxInput], outputs: &[TxOutput]) -> Digest {
    let iv = capacity_iv(TAG_CLAIMS);
    let mut sponge = Poseidon2bSponge::with_iv(iv);

    for inp in inputs.iter().filter(|i| i.valid) {
        sponge.absorb(Block128::from(inp.slot_index as u128));
        sponge.absorb(pack_amount_creation_id(inp.value, inp.creation_id));
        let (hi, lo) = owner_to_fields(&inp.owner.0);
        sponge.absorb(hi);
        sponge.absorb(lo);
    }

    for out in outputs.iter().filter(|o| o.valid) {
        sponge.absorb(Block128::from(out.slot_index as u128));
        sponge.absorb(Block128::from(out.value as u128));
        let (hi, lo) = owner_to_fields(&out.owner.0);
        sponge.absorb(hi);
        sponge.absorb(lo);
    }

    sponge.finalize()
}

#[inline]
fn owner_to_fields(owner: &[u8; 32]) -> (Block128, Block128) {
    let hi = u128::from_le_bytes(owner[..16].try_into().unwrap());
    let lo = u128::from_le_bytes(owner[16..].try_into().unwrap());
    (Block128::from(hi), Block128::from(lo))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, SpendSecret};

    fn mk_input(seed: u8) -> TxInput {
        TxInput {
            slot_index: seed as u32 * 100,
            value: (seed as u64) * 1000,
            creation_id: 0,
            owner: Address([seed; 32]),
            spend_secret: SpendSecret([seed ^ 0xAA; 32]),
            valid: true,
        }
    }

    fn mk_output(seed: u8) -> TxOutput {
        TxOutput {
            slot_index: (seed as u32) * 200,
            value: (seed as u64) * 500,
            owner: Address([seed; 32]),
            valid: true,
        }
    }

    #[test]
    fn deterministic() {
        let inputs = [mk_input(1), mk_input(2)];
        let outputs = [mk_output(3), mk_output(4)];
        let c1 = compute_claims_commitment(&inputs, &outputs);
        let c2 = compute_claims_commitment(&inputs, &outputs);
        assert_eq!(c1, c2);
    }

    #[test]
    fn tamper_input_value_changes_commitment() {
        let inputs = [mk_input(1)];
        let outputs = [mk_output(2)];
        let c1 = compute_claims_commitment(&inputs, &outputs);

        let mut tampered = [mk_input(1)];
        tampered[0].value ^= 1;
        let c2 = compute_claims_commitment(&tampered, &outputs);
        assert_ne!(c1, c2);
    }

    #[test]
    fn tamper_input_creation_id_changes_commitment() {
        let inputs = [mk_input(1)];
        let outputs = [mk_output(2)];
        let c1 = compute_claims_commitment(&inputs, &outputs);

        let mut tampered = [mk_input(1)];
        tampered[0].creation_id = 1;
        let c2 = compute_claims_commitment(&tampered, &outputs);
        assert_ne!(c1, c2);
    }

    #[test]
    fn tamper_input_slot_index_changes_commitment() {
        let inputs = [mk_input(1)];
        let outputs = [mk_output(2)];
        let c1 = compute_claims_commitment(&inputs, &outputs);

        let mut tampered = [mk_input(1)];
        tampered[0].slot_index ^= 7;
        let c2 = compute_claims_commitment(&tampered, &outputs);
        assert_ne!(c1, c2);
    }

    #[test]
    fn tamper_input_owner_changes_commitment() {
        let inputs = [mk_input(1)];
        let outputs = [mk_output(2)];
        let c1 = compute_claims_commitment(&inputs, &outputs);

        let mut tampered = [mk_input(1)];
        tampered[0].owner.0[5] ^= 0xFF;
        let c2 = compute_claims_commitment(&tampered, &outputs);
        assert_ne!(c1, c2);
    }

    #[test]
    fn tamper_output_value_changes_commitment() {
        let inputs = [mk_input(1)];
        let outputs = [mk_output(2)];
        let c1 = compute_claims_commitment(&inputs, &outputs);

        let mut tampered = [mk_output(2)];
        tampered[0].value += 1;
        let c2 = compute_claims_commitment(&inputs, &tampered);
        assert_ne!(c1, c2);
    }

    #[test]
    fn tamper_output_slot_index_changes_commitment() {
        let inputs = [mk_input(1)];
        let outputs = [mk_output(2)];
        let c1 = compute_claims_commitment(&inputs, &outputs);

        let mut tampered = [mk_output(2)];
        tampered[0].slot_index += 1;
        let c2 = compute_claims_commitment(&inputs, &tampered);
        assert_ne!(c1, c2);
    }

    #[test]
    fn dummy_inputs_excluded() {
        let real = mk_input(1);
        let dummy = TxInput::dummy();
        let outputs = [mk_output(2)];

        let c1 = compute_claims_commitment(std::slice::from_ref(&real), &outputs);
        let c2 = compute_claims_commitment(&[real, dummy], &outputs);
        assert_eq!(c1, c2);
    }

    #[test]
    fn dummy_outputs_excluded() {
        let inputs = [mk_input(1)];
        let real = mk_output(2);
        let dummy = TxOutput::dummy();

        let c1 = compute_claims_commitment(&inputs, &[real]);
        let c2 = compute_claims_commitment(&inputs, &[real, dummy]);
        assert_eq!(c1, c2);
    }

    #[test]
    fn order_matters() {
        let i1 = mk_input(1);
        let i2 = mk_input(2);
        let outputs = [mk_output(3)];
        let c1 = compute_claims_commitment(&[i1.clone(), i2.clone()], &outputs);
        let c2 = compute_claims_commitment(&[i2, i1], &outputs);
        assert_ne!(c1, c2);
    }

    #[test]
    fn empty_inputs_and_outputs() {
        let c = compute_claims_commitment(&[], &[]);
        assert_ne!(c, [0u8; 32]);
    }
}
