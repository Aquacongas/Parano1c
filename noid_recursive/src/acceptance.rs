// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Tier-1: proof-carrying acceptance boundary for the O(1) history path.
//!
//! Production `AcceptBlock` (`noid_block::validate_block_full`) already verifies
//! the `BlockProof`/`BlockAuthSidecar`/exact-state transition natively when a
//! block is accepted. That native verification is enough for the accepting node,
//! but a snapshot-syncing node (gap > retained window) never re-runs it — the
//! payloads are pruned. So the recursion must carry a *proof* that the block's
//! execution was verified. That proof is the tier-1 deliverable.
//!
//! Strategy: **Self-Verifying Trace** — the acceptance proof is a
//! zero-check killshot over an arithmetic F128 trace that replays the block's
//! killshot verifiers ([K]), their discharges ([D]), the full verifier of the
//! previous proof ([R] — real recursion), and the receipt/accumulator bindings
//! ([B]). An earlier boolean-R1CS strategy was measured out (one Poseidon2b
//! permutation ≈ 1.69M boolean rows vs ≈ 360 F128-trace constraints) and
//! replaced; the boolean sponge tests below remain as substrate
//! proof-of-life until the cut-over completes.
//!
//! This module currently provides the strategy-independent boundary:
//!   * the [`AcceptanceProof`] envelope (v1; becomes the recursive-proof
//!     envelope),
//!   * the native reference relation [`verify_acceptance_against_projection`],
//!     which binds a [`BlockProofAcceptanceReceipt`] to the locally validated
//!     [`HeaderProjectionSlot`] — pure equality, never re-proving PoW/ASERT/MTP
//!     (this is the [B] slot of the trace), and
//!   * [`shape`] — measured verifier statistics that size the trace.

pub mod block_slots;
pub mod link;
pub mod region;
pub mod shape;
pub mod trace;

use noid_poseidon2b::primitives::Digest;

use crate::block_certificate::BlockProofAcceptanceReceipt;
use crate::header_projection::HeaderProjectionSlot;

/// The tier-1 acceptance proof envelope.
///
/// `receipt` is the public-input surface consumed by the tier-2 chunk.
/// `r1cs_proof` and `deferred_fri_commit` carry the Strategy-B proof material;
/// both are empty/zero until the in-circuit slices land.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptanceProof {
    /// Fixed O(1)-facing output of a successful production `AcceptBlock`.
    pub receipt: BlockProofAcceptanceReceipt,
    /// Running-hash commitment to the deferred FRI openings of the source
    /// `BlockProof` (Strategy B). Accumulated across the chunk/history and
    /// checked once natively at the syncing tip. Zero until the FRI-deferral
    /// slice.
    pub deferred_fri_commit: Digest,
    /// In-circuit algebraic proof (sumcheck/GKR/composition + Poseidon perms +
    /// receipt<->projection binding). Empty until the in-circuit slices land.
    pub r1cs_proof: Vec<u8>,
}

impl AcceptanceProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("serialized AcceptanceProof length fits usize")
            as usize
    }
}

/// Rejection reasons for the receipt<->projection binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceRelationError {
    Height { receipt: u64, projection: u64 },
    BlockId,
    ParentBlockId,
    ChildStateRoot,
    TxRoot,
    ChildLogSlots,
    ChildActiveSlotCount,
    ChildAllocCounter,
}

impl std::fmt::Display for AcceptanceRelationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Height {
                receipt,
                projection,
            } => write!(
                f,
                "acceptance height mismatch: receipt h={receipt}, projection h={projection}"
            ),
            Self::BlockId => write!(f, "acceptance block id does not match header projection"),
            Self::ParentBlockId => {
                write!(f, "acceptance parent block id does not match header projection")
            }
            Self::ChildStateRoot => {
                write!(f, "acceptance child state root does not match header projection")
            }
            Self::TxRoot => write!(f, "acceptance tx root does not match header projection"),
            Self::ChildLogSlots => {
                write!(f, "acceptance child log_slots does not match header projection")
            }
            Self::ChildActiveSlotCount => write!(
                f,
                "acceptance child active_slot_count does not match header projection"
            ),
            Self::ChildAllocCounter => write!(
                f,
                "acceptance child alloc_counter does not match header projection"
            ),
        }
    }
}

impl std::error::Error for AcceptanceRelationError {}

/// Native reference relation for the tier-1 receipt<->header binding.
///
/// It asserts that the child side of a production-acceptance receipt equals the
/// locally validated header projection at that height. This is exactly the set
/// of equalities the in-circuit acceptance proof must enforce as constraints —
/// and nothing more: it must never re-prove PoW, ASERT, MTP, timestamp windows,
/// or cumulative-work arithmetic. Those are header-layer responsibilities; here
/// the projection is a projection of a header the node already validated.
pub fn verify_acceptance_against_projection(
    receipt: &BlockProofAcceptanceReceipt,
    projection: &HeaderProjectionSlot,
) -> Result<(), AcceptanceRelationError> {
    if receipt.height != projection.height {
        return Err(AcceptanceRelationError::Height {
            receipt: receipt.height,
            projection: projection.height,
        });
    }
    if receipt.block_id != projection.block_id {
        return Err(AcceptanceRelationError::BlockId);
    }
    if receipt.parent_block_id != projection.parent_block_id {
        return Err(AcceptanceRelationError::ParentBlockId);
    }
    if receipt.child_state_root != projection.state_root {
        return Err(AcceptanceRelationError::ChildStateRoot);
    }
    if receipt.tx_root != projection.tx_root {
        return Err(AcceptanceRelationError::TxRoot);
    }
    if receipt.child_log_slots != projection.log_slots {
        return Err(AcceptanceRelationError::ChildLogSlots);
    }
    if receipt.child_active_slot_count != projection.active_slot_count {
        return Err(AcceptanceRelationError::ChildActiveSlotCount);
    }
    if receipt.child_alloc_counter != projection.alloc_counter {
        return Err(AcceptanceRelationError::ChildAllocCounter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;

    fn receipt() -> BlockProofAcceptanceReceipt {
        BlockProofAcceptanceReceipt {
            height: 7,
            block_id: [1u8; 32],
            parent_block_id: [2u8; 32],
            parent_state_root: [3u8; 32],
            child_state_root: [4u8; 32],
            tx_root: [5u8; 32],
            parent_log_slots: 24,
            child_log_slots: 24,
            parent_active_slot_count: 40,
            child_active_slot_count: 42,
            parent_alloc_counter: 99,
            child_alloc_counter: 100,
            block_body_digest: [6u8; 32],
            block_proof_digest: [7u8; 32],
            block_proof_meta_digest: [12u8; 32],
            auth_sidecar_digest: [8u8; 32],
            accepted_block_claim_digest: [9u8; 32],
            accepted_state_transition_claim_digest: [10u8; 32],
            exact_transition_digest: [11u8; 32],
            tx_count: 1,
            user_tx_count: 0,
            live_input_count: 0,
            live_output_count: 1,
            state_frontier_node_count: 0,
            touched_slot_count: 1,
            action_count: 1,
            block_body_len: 128,
            block_proof_len: 0,
            auth_sidecar_len: 0,
        }
    }

    fn projection_from(receipt: &BlockProofAcceptanceReceipt) -> HeaderProjectionSlot {
        HeaderProjectionSlot {
            height: receipt.height,
            block_id: receipt.block_id,
            parent_block_id: receipt.parent_block_id,
            state_root: receipt.child_state_root,
            tx_root: receipt.tx_root,
            timestamp: 1_767_225_600,
            miner_address: Address([0x44; 32]),
            nonce: receipt.height as u128,
            difficulty_target: [0x7f; 32],
            log_slots: receipt.child_log_slots,
            active_slot_count: receipt.child_active_slot_count,
            alloc_counter: receipt.child_alloc_counter,
        }
    }

    #[test]
    fn matching_receipt_and_projection_bind() {
        let r = receipt();
        let p = projection_from(&r);
        verify_acceptance_against_projection(&r, &p).expect("binding holds");
    }

    #[test]
    fn binding_is_independent_of_header_consensus_fields() {
        // timestamp / miner_address / nonce / difficulty_target are header
        // consensus fields; tier-1 must not depend on them.
        let r = receipt();
        let mut p = projection_from(&r);
        p.timestamp ^= 0xFFFF;
        p.nonce = p.nonce.wrapping_add(1);
        p.difficulty_target = [0x00; 32];
        p.miner_address = Address([0x99; 32]);
        verify_acceptance_against_projection(&r, &p)
            .expect("binding ignores header consensus fields");
    }

    #[test]
    fn each_bound_field_mismatch_is_rejected() {
        let r = receipt();

        let mut p = projection_from(&r);
        p.height += 1;
        assert!(matches!(
            verify_acceptance_against_projection(&r, &p),
            Err(AcceptanceRelationError::Height { .. })
        ));

        let mut p = projection_from(&r);
        p.block_id = [0xAA; 32];
        assert_eq!(
            verify_acceptance_against_projection(&r, &p),
            Err(AcceptanceRelationError::BlockId)
        );

        let mut p = projection_from(&r);
        p.parent_block_id = [0xAA; 32];
        assert_eq!(
            verify_acceptance_against_projection(&r, &p),
            Err(AcceptanceRelationError::ParentBlockId)
        );

        let mut p = projection_from(&r);
        p.state_root = [0xAA; 32];
        assert_eq!(
            verify_acceptance_against_projection(&r, &p),
            Err(AcceptanceRelationError::ChildStateRoot)
        );

        let mut p = projection_from(&r);
        p.tx_root = [0xAA; 32];
        assert_eq!(
            verify_acceptance_against_projection(&r, &p),
            Err(AcceptanceRelationError::TxRoot)
        );

        let mut p = projection_from(&r);
        p.log_slots += 1;
        assert_eq!(
            verify_acceptance_against_projection(&r, &p),
            Err(AcceptanceRelationError::ChildLogSlots)
        );

        let mut p = projection_from(&r);
        p.active_slot_count += 1;
        assert_eq!(
            verify_acceptance_against_projection(&r, &p),
            Err(AcceptanceRelationError::ChildActiveSlotCount)
        );

        let mut p = projection_from(&r);
        p.alloc_counter += 1;
        assert_eq!(
            verify_acceptance_against_projection(&r, &p),
            Err(AcceptanceRelationError::ChildAllocCounter)
        );
    }

    #[test]
    fn acceptance_proof_envelope_roundtrips() {
        let proof = AcceptanceProof {
            receipt: receipt(),
            deferred_fri_commit: [0u8; 32],
            r1cs_proof: Vec::new(),
        };
        let bytes = bincode::serialize(&proof).expect("serialize");
        let decoded: AcceptanceProof = bincode::deserialize(&bytes).expect("decode");
        assert_eq!(decoded, proof);
        assert!(proof.byte_len() > 0);
    }

    // ---- Slice 2: in-circuit Poseidon2b claim-digest, proved and verified ----
    //
    // De-risks the Strategy-B pipeline end to end on the real substrate: build a
    // boolean R1CS whose gadget computes a Poseidon2b rate-2 sponge in-circuit,
    // pin the squeezed digest to the natively-computed value (the public claim
    // digest binding), then prove and verify with the production IVC prover.
    // This is the `accepted_block_claim_digest` primitive in miniature — the same
    // sponge the acceptance receipt commits to.

    use noid_core::{Block128, TowerField};

    const CLAIM_DIGEST_DOMAIN: &[u8] = b"noid-tier1-claim-digest";

    /// Native reference matching `poseidon2b_sponge_fixed_rate2_bits`: capacity in
    /// lanes 2,3; absorb two fields per permutation into lanes 0,1; squeeze 0,1.
    fn poseidon2b_sponge_rate2_native(fields: &[Block128], capacity: [Block128; 2]) -> [Block128; 2] {
        use noid_poseidon2b::native::permutation::Poseidon2bPermutation;
        let mut state = [Block128::ZERO, Block128::ZERO, capacity[0], capacity[1]];
        for chunk in fields.chunks(2) {
            state[0] = Block128::from(state[0].to_u128() ^ chunk[0].to_u128());
            if let Some(second) = chunk.get(1) {
                state[1] = Block128::from(state[1].to_u128() ^ second.to_u128());
            }
            Poseidon2bPermutation.permute_mut(&mut state);
        }
        [state[0], state[1]]
    }

    #[test]
    fn in_circuit_claim_digest_sponge_proves_and_verifies() {
        use noid_ivc_prover::challenger::{Challenger, FsChallenger};
        use noid_ivc_prover::circuit::{poseidon2b_sponge_fixed_rate2_bits, BinaryR1csBuilder};
        use noid_ivc_prover::pcs::{ligerito::LigeritoProfile, pack_witness, PcsParams};

        let fields = [
            Block128::from(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128),
            Block128::from(0xffff_0000_ffff_0000_aaaa_5555_aaaa_5555u128),
        ];
        let capacity = [
            Block128::from(0x1111_2222_3333_4444_5555_6666_7777_8888u128),
            Block128::from(0xdead_beef_cafe_babe_0123_4567_89ab_cdefu128),
        ];
        let expected = poseidon2b_sponge_rate2_native(&fields, capacity);

        let mut builder = BinaryR1csBuilder::new(21);
        let field_wires: Vec<[usize; 128]> = fields
            .iter()
            .map(|f| builder.alloc_block128(*f).expect("alloc field"))
            .collect();
        let out = poseidon2b_sponge_fixed_rate2_bits(&mut builder, &field_wires, capacity)
            .expect("sponge gadget builds");
        let lo: [usize; 128] = out[..128].try_into().unwrap();
        let hi: [usize; 128] = out[128..].try_into().unwrap();

        // The gadget computes exactly the native digest.
        assert_eq!(builder.block128_value(&lo), expected[0]);
        assert_eq!(builder.block128_value(&hi), expected[1]);

        // Bind the in-circuit output to the public claim digest.
        builder.pin_block128(&lo, expected[0]).expect("pin lo");
        builder.pin_block128(&hi, expected[1]).expect("pin hi");

        let (r1cs, witness) = builder.build();
        assert!(r1cs.satisfies(&witness), "circuit satisfied by its witness");

        let z_packed = pack_witness(&witness, r1cs.m);
        let pcs_params = PcsParams {
            m: r1cs.m,
            log_inv_rate: 4,
            log_batch_size: 5,
            profile: LigeritoProfile::Fast,
        };

        let seed = |ch: &mut FsChallenger| {
            ch.observe_label(b"tier1-claim-digest");
            ch.observe_bytes(&expected[0].to_u128().to_le_bytes());
            ch.observe_bytes(&expected[1].to_u128().to_le_bytes());
        };

        let mut prover_ch = FsChallenger::new(CLAIM_DIGEST_DOMAIN);
        seed(&mut prover_ch);
        let (proof, commitment, _claim) =
            noid_ivc_prover::prover::prove(&r1cs, &z_packed, &pcs_params, &mut prover_ch);

        let mut verifier_ch = FsChallenger::new(CLAIM_DIGEST_DOMAIN);
        seed(&mut verifier_ch);
        noid_ivc_prover::verifier::verify(
            &r1cs,
            &commitment,
            &proof,
            r1cs.csc_lincheck_circuit(),
            &mut verifier_ch,
        )
        .expect("in-circuit claim-digest proof verifies");
    }

    #[test]
    fn wrong_claim_digest_binding_is_unsatisfiable() {
        use noid_ivc_prover::circuit::{poseidon2b_sponge_fixed_rate2_bits, BinaryR1csBuilder};

        let fields = [Block128::from(1u128), Block128::from(2u128)];
        let capacity = [Block128::from(3u128), Block128::from(4u128)];
        let expected = poseidon2b_sponge_rate2_native(&fields, capacity);

        let mut builder = BinaryR1csBuilder::new(21);
        let field_wires: Vec<[usize; 128]> = fields
            .iter()
            .map(|f| builder.alloc_block128(*f).expect("alloc field"))
            .collect();
        let out = poseidon2b_sponge_fixed_rate2_bits(&mut builder, &field_wires, capacity)
            .expect("sponge gadget builds");
        let lo: [usize; 128] = out[..128].try_into().unwrap();

        // Pin the squeezed digest to a WRONG value: no witness can satisfy it,
        // so a prover cannot forge a claim digest for these inputs.
        let wrong = Block128::from(expected[0].to_u128() ^ 1);
        builder.pin_block128(&lo, wrong).expect("pin wrong");

        let (r1cs, witness) = builder.build();
        assert!(
            !r1cs.satisfies(&witness),
            "binding to a wrong claim digest must be unsatisfiable"
        );
    }
}
