// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Accepted-block claim batch relation.
//!
//! This is the native specification boundary for the production O(1) batch
//! step: a consecutive header-work batch plus one canonical accepted-block
//! claim per header. The optimized recursive implementation must prove exactly
//! this transition, then replace the native verifier as public authority.

use noid_core::Block128;
use noid_gkr::{ChainAccumulatorBatchInputs, ChainAccumulatorItem};

use crate::accumulator::ChainAccumulator;
use crate::header_integer::{
    verify_header_integer_trace, HeaderIntegerBatchTrace, HeaderIntegerTraceError,
};
use crate::pow_header::{
    verify_pow_header_witness_batch_native, HeaderWitness, PowHeaderBatchError,
    RecursiveConsensusState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedClaimBatchWitness {
    pub headers: Vec<HeaderWitness>,
    pub accepted_block_claims: Vec<[Block128; 2]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedClaimBatchOutput {
    pub consensus_state: RecursiveConsensusState,
    pub accumulator: ChainAccumulator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedClaimBatchError {
    EmptyBatch,
    ClaimCountMismatch { headers: usize, claims: usize },
    StartStateMismatch,
    HeaderWork(PowHeaderBatchError),
    HeaderInteger(HeaderIntegerTraceError),
}

fn digest_to_fields(hash: [u8; 32]) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
    ]
}

pub fn chain_accumulator_proof_inputs(
    start_accumulator: &ChainAccumulator,
    accepted_witness: &AcceptedClaimBatchWitness,
    end_accumulator: &ChainAccumulator,
) -> ChainAccumulatorBatchInputs {
    let items = accepted_witness
        .headers
        .iter()
        .zip(accepted_witness.accepted_block_claims.iter().copied())
        .map(|(header_witness, chain_claim)| ChainAccumulatorItem {
            block_id: digest_to_fields(header_witness.block_id),
            chain_claim,
        })
        .collect();
    ChainAccumulatorBatchInputs {
        start_chain_hash: digest_to_fields(start_accumulator.chain_hash),
        items,
        expected_chain_hash: digest_to_fields(end_accumulator.chain_hash),
    }
}

pub fn verify_accepted_claim_batch_native(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    witness: &AcceptedClaimBatchWitness,
) -> Result<AcceptedClaimBatchOutput, AcceptedClaimBatchError> {
    if witness.headers.is_empty() {
        return Err(AcceptedClaimBatchError::EmptyBatch);
    }
    if witness.headers.len() != witness.accepted_block_claims.len() {
        return Err(AcceptedClaimBatchError::ClaimCountMismatch {
            headers: witness.headers.len(),
            claims: witness.accepted_block_claims.len(),
        });
    }
    if start_accumulator.height != start_consensus.height
        || start_accumulator.state_root != start_consensus.state_root
    {
        return Err(AcceptedClaimBatchError::StartStateMismatch);
    }

    let consensus_state = verify_pow_header_witness_batch_native(start_consensus, &witness.headers)
        .map_err(AcceptedClaimBatchError::HeaderWork)?;

    let mut accumulator = start_accumulator.clone();
    for (header_witness, chain_claim) in witness
        .headers
        .iter()
        .zip(witness.accepted_block_claims.iter().copied())
    {
        accumulator = accumulator.extend(
            header_witness.header.state_root,
            header_witness.block_id,
            header_witness.header.height,
            chain_claim,
        );
    }

    if accumulator.height != consensus_state.height
        || accumulator.state_root != consensus_state.state_root
    {
        return Err(AcceptedClaimBatchError::StartStateMismatch);
    }

    Ok(AcceptedClaimBatchOutput {
        consensus_state,
        accumulator,
    })
}

/// Verify the accepted-claim batch using the split header-work boundary.
///
/// This function does not recompute Poseidon2b header hashes. It is valid only
/// when paired with `HeaderHashProofKillShot` over the same header witnesses.
pub fn verify_accepted_claim_batch_with_header_trace(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    witness: &AcceptedClaimBatchWitness,
    header_trace: &HeaderIntegerBatchTrace,
) -> Result<AcceptedClaimBatchOutput, AcceptedClaimBatchError> {
    if witness.headers.is_empty() {
        return Err(AcceptedClaimBatchError::EmptyBatch);
    }
    if witness.headers.len() != witness.accepted_block_claims.len() {
        return Err(AcceptedClaimBatchError::ClaimCountMismatch {
            headers: witness.headers.len(),
            claims: witness.accepted_block_claims.len(),
        });
    }
    if start_accumulator.height != start_consensus.height
        || start_accumulator.state_root != start_consensus.state_root
    {
        return Err(AcceptedClaimBatchError::StartStateMismatch);
    }

    let consensus_state =
        verify_header_integer_trace(start_consensus, &witness.headers, header_trace)
            .map_err(AcceptedClaimBatchError::HeaderInteger)?;

    let mut accumulator = start_accumulator.clone();
    for (header_witness, chain_claim) in witness
        .headers
        .iter()
        .zip(witness.accepted_block_claims.iter().copied())
    {
        accumulator = accumulator.extend(
            header_witness.header.state_root,
            header_witness.block_id,
            header_witness.header.height,
            chain_claim,
        );
    }

    if accumulator.height != consensus_state.height
        || accumulator.state_root != consensus_state.state_root
    {
        return Err(AcceptedClaimBatchError::StartStateMismatch);
    }

    Ok(AcceptedClaimBatchOutput {
        consensus_state,
        accumulator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_integer::build_header_integer_trace;
    use noid_chain::consensus::difficulty::{add_work, block_work, next_target};
    use noid_chain::consensus::epoch_anchor_height;
    use noid_chain::consensus::params::{BLOCK_TIME, MAX_TARGET};
    use noid_gkr::{prove_chain_accumulator_killshot, verify_chain_accumulator_killshot};
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use noid_poseidon2b::primitives::Address;

    fn verify_without_pow_for_tests(
        start_consensus: &RecursiveConsensusState,
        start_accumulator: &ChainAccumulator,
        witness: &AcceptedClaimBatchWitness,
    ) -> Result<AcceptedClaimBatchOutput, AcceptedClaimBatchError> {
        if witness.headers.len() != witness.accepted_block_claims.len() {
            return Err(AcceptedClaimBatchError::ClaimCountMismatch {
                headers: witness.headers.len(),
                claims: witness.accepted_block_claims.len(),
            });
        }
        let mut consensus = start_consensus.clone();
        let mut accumulator = start_accumulator.clone();
        for (index, header_witness) in witness.headers.iter().enumerate() {
            if header_witness.header.prev_block_hash != consensus.block_id {
                return Err(AcceptedClaimBatchError::HeaderWork(
                    PowHeaderBatchError::BadParentLink { index },
                ));
            }
            if header_witness.header.height != consensus.height + 1 {
                return Err(AcceptedClaimBatchError::HeaderWork(
                    PowHeaderBatchError::BadHeight { index },
                ));
            }
            if header_witness.block_id != noid_chain::hash_block_header(&header_witness.header) {
                return Err(AcceptedClaimBatchError::HeaderWork(
                    PowHeaderBatchError::BadHeaderWitness {
                        index,
                        reason: crate::pow_header::HeaderWitnessError::BadBlockId,
                    },
                ));
            }
            let chain_claim = witness.accepted_block_claims[index];
            consensus.height = header_witness.header.height;
            consensus.block_id = header_witness.block_id;
            consensus.state_root = header_witness.header.state_root;
            accumulator = accumulator.extend(
                header_witness.header.state_root,
                header_witness.block_id,
                header_witness.header.height,
                chain_claim,
            );
        }
        Ok(AcceptedClaimBatchOutput {
            consensus_state: consensus,
            accumulator,
        })
    }

    fn start_header() -> noid_chain::BlockHeader {
        noid_chain::BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [1u8; 32],
            tx_root: [0u8; 32],
            timestamp: 1_767_225_600,
            height: 0,
            miner_address: Address([0x44; 32]),
            nonce: 0,
            difficulty_target: MAX_TARGET,
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    fn next_header(state: &RecursiveConsensusState, state_seed: u8) -> noid_chain::BlockHeader {
        let height = state.height + 1;
        let timestamp = state.mtp_timestamps[(state.mtp_len - 1) as usize] + BLOCK_TIME;
        noid_chain::BlockHeader {
            prev_block_hash: state.block_id,
            state_root: [state_seed; 32],
            tx_root: [state_seed ^ 0x55; 32],
            timestamp,
            height,
            miner_address: Address([0x55; 32]),
            nonce: height as u128,
            difficulty_target: next_target(
                state.asert_anchor_height,
                state.asert_anchor_timestamp,
                &state.asert_anchor_target,
                height,
                timestamp,
            ),
            log_slots: state.log_slots,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        }
    }

    fn start_pair() -> (RecursiveConsensusState, ChainAccumulator) {
        let header = start_header();
        let start_consensus = RecursiveConsensusState::from_header(
            &header,
            block_work(&header.difficulty_target),
            0,
            header.timestamp,
            header.difficulty_target,
            &[header.timestamp],
            &[header.active_slot_count],
        );
        let start_accumulator = ChainAccumulator {
            height: header.height,
            state_root: header.state_root,
            chain_hash: [0u8; 32],
        };
        (start_consensus, start_accumulator)
    }

    fn advance_consensus_for_tests(
        state: &RecursiveConsensusState,
        header: &noid_chain::BlockHeader,
        block_id: [u8; 32],
    ) -> RecursiveConsensusState {
        let mut next = state.clone();
        next.height = header.height;
        next.block_id = block_id;
        next.state_root = header.state_root;
        next.cumulative_chainwork = add_work(
            &next.cumulative_chainwork,
            &block_work(&header.difficulty_target),
        );
        next.log_slots = header.log_slots;
        next.active_slot_count = header.active_slot_count;
        next.alloc_counter = header.alloc_counter;
        next.push_timestamp(header.timestamp);
        next.push_active_count(header.active_slot_count);
        if epoch_anchor_height(header.height) == header.height {
            next.asert_anchor_height = header.height;
            next.asert_anchor_timestamp = header.timestamp;
            next.asert_anchor_target = header.difficulty_target;
        }
        next
    }

    fn integer_witness(header: &noid_chain::BlockHeader) -> HeaderWitness {
        let mut witness = HeaderWitness::from_header(header);
        witness.pow_digest = [0u8; 32];
        witness
    }

    #[test]
    fn accepted_claim_batch_updates_consensus_and_accumulator() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let mut mid = start_consensus.clone();
        mid.height = h1.height;
        mid.block_id = noid_chain::hash_block_header(&h1);
        mid.state_root = h1.state_root;
        let h2 = next_header(&mid, 3);
        let claims = vec![
            [Block128::from(0xA1u128), Block128::from(0xA2u128)],
            [Block128::from(0xB1u128), Block128::from(0xB2u128)],
        ];
        let witness = AcceptedClaimBatchWitness {
            headers: vec![
                HeaderWitness::from_header(&h1),
                HeaderWitness::from_header(&h2),
            ],
            accepted_block_claims: claims.clone(),
        };

        let out =
            verify_without_pow_for_tests(&start_consensus, &start_accumulator, &witness).unwrap();
        assert_eq!(out.consensus_state.height, 2);
        assert_eq!(out.consensus_state.state_root, h2.state_root);

        let expected = start_accumulator
            .extend(
                h1.state_root,
                noid_chain::hash_block_header(&h1),
                h1.height,
                claims[0],
            )
            .extend(
                h2.state_root,
                noid_chain::hash_block_header(&h2),
                h2.height,
                claims[1],
            );
        assert_eq!(out.accumulator, expected);
    }

    #[test]
    fn accepted_claim_batch_feeds_chain_accumulator_killshot() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let mut mid = start_consensus.clone();
        mid.height = h1.height;
        mid.block_id = noid_chain::hash_block_header(&h1);
        mid.state_root = h1.state_root;
        let h2 = next_header(&mid, 3);
        let witness = AcceptedClaimBatchWitness {
            headers: vec![
                HeaderWitness::from_header(&h1),
                HeaderWitness::from_header(&h2),
            ],
            accepted_block_claims: vec![
                [Block128::from(0xA1u128), Block128::from(0xA2u128)],
                [Block128::from(0xB1u128), Block128::from(0xB2u128)],
            ],
        };
        let out =
            verify_without_pow_for_tests(&start_consensus, &start_accumulator, &witness).unwrap();
        let inputs = chain_accumulator_proof_inputs(&start_accumulator, &witness, &out.accumulator);

        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) = prove_chain_accumulator_killshot(&inputs, &mut ch_p);
        let mut ch_v = Poseidon2bChannel::new();
        let verified = verify_chain_accumulator_killshot(&proof, &inputs, &mut ch_v)
            .expect("accepted batch accumulator proof verifies");
        assert_eq!(verified, reductions);
    }

    #[test]
    fn accepted_claim_batch_with_header_trace_updates_consensus_and_accumulator() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let w1 = integer_witness(&h1);
        let mid = advance_consensus_for_tests(&start_consensus, &h1, w1.block_id);
        let h2 = next_header(&mid, 3);
        let w2 = integer_witness(&h2);
        let witness = AcceptedClaimBatchWitness {
            headers: vec![w1, w2],
            accepted_block_claims: vec![
                [Block128::from(0xA1u128), Block128::from(0xA2u128)],
                [Block128::from(0xB1u128), Block128::from(0xB2u128)],
            ],
        };
        let trace = build_header_integer_trace(&start_consensus, &witness.headers).unwrap();

        let out = verify_accepted_claim_batch_with_header_trace(
            &start_consensus,
            &start_accumulator,
            &witness,
            &trace,
        )
        .unwrap();

        assert_eq!(out.consensus_state.height, h2.height);
        assert_eq!(
            out.consensus_state.block_id,
            noid_chain::hash_block_header(&h2)
        );
        assert_eq!(out.consensus_state.state_root, h2.state_root);
        assert_eq!(out.accumulator.height, h2.height);
        assert_eq!(out.accumulator.state_root, h2.state_root);
    }

    #[test]
    fn accepted_claim_batch_with_header_trace_rejects_pow_equality() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let mut witness_header = HeaderWitness::from_header(&h1);
        witness_header.pow_digest = h1.difficulty_target;
        let witness = AcceptedClaimBatchWitness {
            headers: vec![witness_header],
            accepted_block_claims: vec![[Block128::from(1u128), Block128::from(2u128)]],
        };
        let trace = build_header_integer_trace(&start_consensus, &witness.headers).unwrap();

        assert_eq!(
            verify_accepted_claim_batch_with_header_trace(
                &start_consensus,
                &start_accumulator,
                &witness,
                &trace,
            ),
            Err(AcceptedClaimBatchError::HeaderInteger(
                HeaderIntegerTraceError::BadPowTarget { index: 0 }
            ))
        );
    }

    #[test]
    fn accepted_claim_batch_rejects_claim_count_mismatch() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let witness = AcceptedClaimBatchWitness {
            headers: vec![HeaderWitness::from_header(&h1)],
            accepted_block_claims: vec![],
        };
        assert!(matches!(
            verify_without_pow_for_tests(&start_consensus, &start_accumulator, &witness),
            Err(AcceptedClaimBatchError::ClaimCountMismatch {
                headers: 1,
                claims: 0
            })
        ));
    }

    #[test]
    fn accepted_claim_batch_rejects_bad_parent_link() {
        let (start_consensus, start_accumulator) = start_pair();
        let mut h1 = next_header(&start_consensus, 2);
        h1.prev_block_hash = [9u8; 32];
        let witness = AcceptedClaimBatchWitness {
            headers: vec![HeaderWitness::from_header(&h1)],
            accepted_block_claims: vec![[Block128::from(1u128), Block128::from(2u128)]],
        };
        assert!(matches!(
            verify_without_pow_for_tests(&start_consensus, &start_accumulator, &witness),
            Err(AcceptedClaimBatchError::HeaderWork(
                PowHeaderBatchError::BadParentLink { index: 0 }
            ))
        ));
    }
}
