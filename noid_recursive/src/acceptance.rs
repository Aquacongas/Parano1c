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
//!   * the native reference relation [`verify_acceptance_against_header`],
//!     which binds a [`BlockProofAcceptanceReceipt`] to the locally validated
//!     canonical header directly — equality plus local block-id recomputation,
//!     never re-proving PoW/ASERT/MTP (this is the [B] slot of the trace), and
//!   * [`shape`] — measured verifier statistics that size the trace.

pub mod block_class;
pub mod block_slots;
pub mod link;
pub mod shape;
pub mod split_link;
pub mod trace;
pub mod zk_auth_capsule_schedule;

/// Env-gated (`NOID_ROW_LEDGER=1`) wire-count checkpoint: prints the delta
/// since the previous mark and the running total. The Stage-0 per-subsystem
/// row ledger — zero cost when the variable is unset.
pub(crate) fn row_ledger_mark(
    b: &noid_ivc_core::field_circuit::FieldR1csBuilder,
    last: &mut usize,
    label: &str,
) {
    if std::env::var_os("NOID_ROW_LEDGER").is_some() {
        let now = b.num_wires();
        eprintln!(
            "[ledger] {label:<32} +{:>9}  (total {:>9})",
            now - *last,
            now
        );
        *last = now;
    }
}

/// Expand a naturally dyadic one-block Field trace to its frozen protocol
/// shape without allocating identity constraints in the zero tail.
pub(crate) fn expand_empty_field_tail(
    mut r1cs: noid_ivc_core::field_r1cs::FieldR1cs,
    mut witness: Vec<noid_ivc_core::field::F128>,
    shape: noid_ivc_core::proof::FieldShape,
) -> (
    noid_ivc_core::field_r1cs::FieldR1cs,
    Vec<noid_ivc_core::field::F128>,
) {
    use noid_ivc_core::field::F128;

    assert_eq!(r1cs.m, r1cs.k_log, "builder emits one base block");
    assert_eq!(shape.m, shape.k_log, "class must use one base block");
    assert_eq!(r1cs.k_skip, shape.k_skip, "class k_skip drift");
    assert_eq!(r1cs.const_pin, shape.const_pin, "class const pin drift");
    assert!(r1cs.m <= shape.m, "cannot shrink a built Field class");
    assert!(
        r1cs.digest_cache.get().is_none() && r1cs.csc_cache.get().is_none(),
        "padding must precede matrix digest/CSC caching"
    );
    let natural_rows = 1usize << r1cs.k_log;
    let target_rows = 1usize << shape.k_log;
    assert_eq!(witness.len(), natural_rows, "natural witness size");
    assert!(
        witness[r1cs.useful_rows..]
            .iter()
            .all(|value| *value == F128::ZERO),
        "natural builder padding witness must be zero"
    );
    for matrix in [&r1cs.a_0, &r1cs.b_0] {
        assert!(
            matrix.row_offsets[r1cs.useful_rows..]
                .windows(2)
                .all(|pair| pair[0] == pair[1]),
            "natural builder padding rows must be empty"
        );
    }
    let expand = |matrix: &mut noid_ivc_core::field_r1cs::SparseFieldMatrix| {
        let terminal = *matrix.row_offsets.last().expect("CSR terminal offset");
        matrix.row_offsets.resize(target_rows + 1, terminal);
        matrix.num_rows = target_rows;
        matrix.num_cols = target_rows;
    };
    expand(&mut r1cs.a_0);
    expand(&mut r1cs.b_0);
    witness.resize(target_rows, F128::ZERO);
    r1cs.m = shape.m;
    r1cs.k_log = shape.k_log;
    r1cs.validate_shape();
    assert!(
        witness[r1cs.useful_rows..]
            .iter()
            .all(|value| *value == F128::ZERO),
        "expanded Field padding witness must be zero"
    );
    (r1cs, witness)
}

use noid_chain::block_header::{hash_block_header, BlockHeader};
use noid_poseidon2b::primitives::Digest;

use crate::block_certificate::BlockProofAcceptanceReceipt;

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
    /// receipt<->local-header binding). Empty until the in-circuit slices land.
    pub r1cs_proof: Vec<u8>,
}

impl AcceptanceProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("serialized AcceptanceProof length fits usize")
            as usize
    }
}

/// Rejection reasons for the receipt<->local-header binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceRelationError {
    Height { receipt: u64, header: u64 },
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
            Self::Height { receipt, header } => write!(
                f,
                "acceptance height mismatch: receipt h={receipt}, local header h={header}"
            ),
            Self::BlockId => write!(f, "acceptance block id does not match local header"),
            Self::ParentBlockId => {
                write!(f, "acceptance parent block id does not match local header")
            }
            Self::ChildStateRoot => {
                write!(f, "acceptance child state root does not match local header")
            }
            Self::TxRoot => write!(f, "acceptance tx root does not match local header"),
            Self::ChildLogSlots => {
                write!(f, "acceptance child log_slots does not match local header")
            }
            Self::ChildActiveSlotCount => write!(
                f,
                "acceptance child active_slot_count does not match local header"
            ),
            Self::ChildAllocCounter => write!(
                f,
                "acceptance child alloc_counter does not match local header"
            ),
        }
    }
}

impl std::error::Error for AcceptanceRelationError {}

/// Native reference relation for the tier-1 receipt<->local-header binding.
///
/// It asserts that the child side of a production-acceptance receipt equals the
/// locally validated header at that height. The block id is recomputed from the
/// header, so it also commits to every header consensus field and the ancestry
/// link. PoW, ASERT, MTP, timestamp windows, cumulative work, and fork choice
/// remain native header-layer responsibilities.
pub fn verify_acceptance_against_header(
    receipt: &BlockProofAcceptanceReceipt,
    header: &BlockHeader,
) -> Result<(), AcceptanceRelationError> {
    if receipt.height != header.height {
        return Err(AcceptanceRelationError::Height {
            receipt: receipt.height,
            header: header.height,
        });
    }
    if receipt.block_id != hash_block_header(header) {
        return Err(AcceptanceRelationError::BlockId);
    }
    if receipt.parent_block_id != header.prev_block_hash {
        return Err(AcceptanceRelationError::ParentBlockId);
    }
    if receipt.child_state_root != header.state_root {
        return Err(AcceptanceRelationError::ChildStateRoot);
    }
    if receipt.tx_root != header.tx_root {
        return Err(AcceptanceRelationError::TxRoot);
    }
    if receipt.child_log_slots != header.log_slots {
        return Err(AcceptanceRelationError::ChildLogSlots);
    }
    if receipt.child_active_slot_count != header.active_slot_count {
        return Err(AcceptanceRelationError::ChildActiveSlotCount);
    }
    if receipt.child_alloc_counter != header.alloc_counter {
        return Err(AcceptanceRelationError::ChildAllocCounter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;

    fn local_header() -> BlockHeader {
        BlockHeader {
            prev_block_hash: [2u8; 32],
            state_root: [4u8; 32],
            tx_root: [5u8; 32],
            timestamp: 1_767_225_600,
            height: 7,
            miner_address: Address([0x44; 32]),
            nonce: 7,
            difficulty_target: [0x7f; 32],
            log_slots: 24,
            active_slot_count: 42,
            alloc_counter: 100,
        }
    }

    fn receipt() -> BlockProofAcceptanceReceipt {
        let header = local_header();
        BlockProofAcceptanceReceipt {
            height: header.height,
            block_id: hash_block_header(&header),
            parent_block_id: header.prev_block_hash,
            parent_state_root: [3u8; 32],
            child_state_root: header.state_root,
            tx_root: header.tx_root,
            parent_log_slots: 24,
            child_log_slots: header.log_slots,
            parent_active_slot_count: 40,
            child_active_slot_count: header.active_slot_count,
            parent_alloc_counter: 99,
            child_alloc_counter: header.alloc_counter,
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

    #[test]
    fn matching_receipt_and_local_header_bind() {
        let r = receipt();
        verify_acceptance_against_header(&r, &local_header()).expect("binding holds");
    }

    #[test]
    fn block_id_binding_commits_every_header_consensus_field() {
        let r = receipt();
        for mutated in [
            {
                let mut h = local_header();
                h.timestamp ^= 0xFFFF;
                h
            },
            {
                let mut h = local_header();
                h.nonce = h.nonce.wrapping_add(1);
                h
            },
            {
                let mut h = local_header();
                h.difficulty_target = [0x00; 32];
                h
            },
            {
                let mut h = local_header();
                h.miner_address = Address([0x99; 32]);
                h
            },
        ] {
            assert_eq!(
                verify_acceptance_against_header(&r, &mutated),
                Err(AcceptanceRelationError::BlockId)
            );
        }
    }

    #[test]
    fn each_bound_field_mismatch_is_rejected() {
        let r = receipt();

        let mut p = local_header();
        p.height += 1;
        assert!(matches!(
            verify_acceptance_against_header(&r, &p),
            Err(AcceptanceRelationError::Height { .. })
        ));

        let mut bad_id = r.clone();
        bad_id.block_id = [0xAA; 32];
        assert_eq!(
            verify_acceptance_against_header(&bad_id, &local_header()),
            Err(AcceptanceRelationError::BlockId)
        );

        let mut p = local_header();
        p.prev_block_hash = [0xAA; 32];
        let mut matching_id = r.clone();
        matching_id.block_id = hash_block_header(&p);
        assert_eq!(
            verify_acceptance_against_header(&matching_id, &p),
            Err(AcceptanceRelationError::ParentBlockId)
        );

        let mut p = local_header();
        p.state_root = [0xAA; 32];
        let mut matching_id = r.clone();
        matching_id.block_id = hash_block_header(&p);
        assert_eq!(
            verify_acceptance_against_header(&matching_id, &p),
            Err(AcceptanceRelationError::ChildStateRoot)
        );

        let mut p = local_header();
        p.tx_root = [0xAA; 32];
        let mut matching_id = r.clone();
        matching_id.block_id = hash_block_header(&p);
        assert_eq!(
            verify_acceptance_against_header(&matching_id, &p),
            Err(AcceptanceRelationError::TxRoot)
        );

        let mut p = local_header();
        p.log_slots += 1;
        let mut matching_id = r.clone();
        matching_id.block_id = hash_block_header(&p);
        assert_eq!(
            verify_acceptance_against_header(&matching_id, &p),
            Err(AcceptanceRelationError::ChildLogSlots)
        );

        let mut p = local_header();
        p.active_slot_count += 1;
        let mut matching_id = r.clone();
        matching_id.block_id = hash_block_header(&p);
        assert_eq!(
            verify_acceptance_against_header(&matching_id, &p),
            Err(AcceptanceRelationError::ChildActiveSlotCount)
        );

        let mut p = local_header();
        p.alloc_counter += 1;
        let mut matching_id = r.clone();
        matching_id.block_id = hash_block_header(&p);
        assert_eq!(
            verify_acceptance_against_header(&matching_id, &p),
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
    fn poseidon2b_sponge_rate2_native(
        fields: &[Block128],
        capacity: [Block128; 2],
    ) -> [Block128; 2] {
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
