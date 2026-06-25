// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Checkpoint proof components for the Poseidon2b-heavy recursive path.
//!
//! This module contains the proof object for the parts of a checkpoint batch
//! that are already arithmetic and KillShot-native:
//!
//! - canonical semantic-header and PoW-header Poseidon2b hashing;
//! - rolling chain-accumulator compression.
//!
//! It is deliberately not public snapshot authority by itself. Header integer
//! rules and the full block-validity relation are separate proof obligations.

use noid_chain::consensus::pow::pow_header_fields;
use noid_gkr::{
    discharge_chain_accumulator_reductions_native, discharge_header_hash_reductions_native,
    prove_chain_accumulator_killshot, prove_header_hash_killshot,
    verify_chain_accumulator_killshot, verify_header_hash_killshot, ChainAccumulatorProofKillShot,
    HeaderHashProofKillShot,
};
use noid_poseidon2b::channel::Poseidon2bChannel;

use crate::accepted_batch::{chain_accumulator_proof_inputs, AcceptedClaimBatchWitness};
use crate::accumulator::ChainAccumulator;
use crate::pow_header::header_hash_proof_inputs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPoseidonProof {
    pub header_hash: HeaderHashProofKillShot,
    pub chain_accumulator: ChainAccumulatorProofKillShot,
    pub n_blocks: usize,
}

impl CheckpointPoseidonProof {
    pub fn byte_len(&self) -> usize {
        self.header_hash.byte_len() + self.chain_accumulator.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointPoseidonError {
    EmptyBatch,
    ClaimCountMismatch { headers: usize, claims: usize },
    HeaderFieldMismatch { index: usize },
    HeaderTargetMismatch { index: usize },
    AccumulatorStartMismatch,
    AccumulatorEndMismatch,
    HeaderHashProofRejected,
    ChainAccumulatorProofRejected,
}

fn validate_shape(witness: &AcceptedClaimBatchWitness) -> Result<(), CheckpointPoseidonError> {
    if witness.headers.is_empty() {
        return Err(CheckpointPoseidonError::EmptyBatch);
    }
    if witness.headers.len() != witness.accepted_block_claims.len() {
        return Err(CheckpointPoseidonError::ClaimCountMismatch {
            headers: witness.headers.len(),
            claims: witness.accepted_block_claims.len(),
        });
    }
    for (index, header_witness) in witness.headers.iter().enumerate() {
        if header_witness.pow_fields != pow_header_fields(&header_witness.header) {
            return Err(CheckpointPoseidonError::HeaderFieldMismatch { index });
        }
        if header_witness.target != header_witness.header.difficulty_target {
            return Err(CheckpointPoseidonError::HeaderTargetMismatch { index });
        }
    }
    Ok(())
}

fn validate_accumulator_boundary(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    witness: &AcceptedClaimBatchWitness,
) -> Result<(), CheckpointPoseidonError> {
    let first = witness
        .headers
        .first()
        .ok_or(CheckpointPoseidonError::EmptyBatch)?;
    if first.header.height != start_accumulator.height + 1 {
        return Err(CheckpointPoseidonError::AccumulatorStartMismatch);
    }
    let last = witness
        .headers
        .last()
        .ok_or(CheckpointPoseidonError::EmptyBatch)?;
    if end_accumulator.height != last.header.height
        || end_accumulator.state_root != last.header.state_root
    {
        return Err(CheckpointPoseidonError::AccumulatorEndMismatch);
    }
    Ok(())
}

/// Build the Poseidon2b checkpoint component proof.
///
/// The caller must separately prove or verify header integer consensus and the
/// full accepted-block relation before treating this checkpoint as authority.
pub fn prove_checkpoint_poseidon(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    witness: &AcceptedClaimBatchWitness,
) -> Result<CheckpointPoseidonProof, CheckpointPoseidonError> {
    validate_shape(witness)?;
    validate_accumulator_boundary(start_accumulator, end_accumulator, witness)?;

    let header_inputs = header_hash_proof_inputs(&witness.headers);
    let chain_inputs = chain_accumulator_proof_inputs(start_accumulator, witness, end_accumulator);
    let (header_hash, chain_accumulator) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            prove_header_hash_killshot(&header_inputs, &mut channel).0
        },
        || {
            let mut channel = Poseidon2bChannel::new();
            prove_chain_accumulator_killshot(&chain_inputs, &mut channel).0
        },
    );

    Ok(CheckpointPoseidonProof {
        header_hash,
        chain_accumulator,
        n_blocks: witness.headers.len(),
    })
}

/// Verify the Poseidon2b checkpoint component proof.
///
/// This verifier checks no native Poseidon2b digests. The header hash proof
/// binds the supplied canonical field schedule to `pow_digest` and `block_id`,
/// and the accumulator proof binds those block ids plus accepted claims into
/// the end accumulator.
pub fn verify_checkpoint_poseidon(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    witness: &AcceptedClaimBatchWitness,
    proof: &CheckpointPoseidonProof,
) -> Result<(), CheckpointPoseidonError> {
    validate_shape(witness)?;
    validate_accumulator_boundary(start_accumulator, end_accumulator, witness)?;
    if proof.n_blocks != witness.headers.len() {
        return Err(CheckpointPoseidonError::ClaimCountMismatch {
            headers: proof.n_blocks,
            claims: witness.headers.len(),
        });
    }

    let header_inputs = header_hash_proof_inputs(&witness.headers);
    let chain_inputs = chain_accumulator_proof_inputs(start_accumulator, witness, end_accumulator);
    let (header_result, chain_result) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            let reductions =
                verify_header_hash_killshot(&proof.header_hash, &header_inputs, &mut channel)
                    .ok_or(CheckpointPoseidonError::HeaderHashProofRejected)?;
            if discharge_header_hash_reductions_native(&header_inputs, &reductions) {
                Ok(())
            } else {
                Err(CheckpointPoseidonError::HeaderHashProofRejected)
            }
        },
        || {
            let mut channel = Poseidon2bChannel::new();
            let reductions = verify_chain_accumulator_killshot(
                &proof.chain_accumulator,
                &chain_inputs,
                &mut channel,
            )
            .ok_or(CheckpointPoseidonError::ChainAccumulatorProofRejected)?;
            if discharge_chain_accumulator_reductions_native(&chain_inputs, &reductions) {
                Ok(())
            } else {
                Err(CheckpointPoseidonError::ChainAccumulatorProofRejected)
            }
        },
    );
    header_result?;
    chain_result?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow_header::HeaderWitness;
    use noid_chain::consensus::params::MAX_TARGET;
    use noid_core::{Block128, TowerField};
    use noid_poseidon2b::primitives::Address;

    fn header(height: u64, prev: [u8; 32], state_seed: u8) -> noid_chain::BlockHeader {
        noid_chain::BlockHeader {
            prev_block_hash: prev,
            state_root: [state_seed; 32],
            tx_root: [state_seed ^ 0x55; 32],
            timestamp: 1_767_225_600 + height * 15,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: MAX_TARGET,
            log_slots: 24,
            active_slot_count: height,
            alloc_counter: height,
        }
    }

    fn fixture() -> (
        ChainAccumulator,
        ChainAccumulator,
        AcceptedClaimBatchWitness,
    ) {
        let start = ChainAccumulator {
            height: 0,
            state_root: [1u8; 32],
            chain_hash: [0u8; 32],
        };
        let h1 = header(1, [0u8; 32], 2);
        let w1 = HeaderWitness::from_header(&h1);
        let claim1 = [Block128::from(0xA1u128), Block128::from(0xA2u128)];
        let acc1 = start.extend(h1.state_root, w1.block_id, h1.height, claim1);
        let h2 = header(2, w1.block_id, 3);
        let w2 = HeaderWitness::from_header(&h2);
        let claim2 = [Block128::from(0xB1u128), Block128::from(0xB2u128)];
        let end = acc1.extend(h2.state_root, w2.block_id, h2.height, claim2);
        let witness = AcceptedClaimBatchWitness {
            headers: vec![w1, w2],
            accepted_block_claims: vec![claim1, claim2],
        };
        (start, end, witness)
    }

    #[test]
    fn checkpoint_poseidon_roundtrip() {
        let (start, end, witness) = fixture();
        let proof = prove_checkpoint_poseidon(&start, &end, &witness).unwrap();
        verify_checkpoint_poseidon(&start, &end, &witness, &proof).unwrap();
        assert!(proof.byte_len() > 0);
    }

    #[test]
    fn checkpoint_poseidon_rejects_header_field_split() {
        let (start, end, mut witness) = fixture();
        let proof = prove_checkpoint_poseidon(&start, &end, &witness).unwrap();
        witness.headers[0].pow_fields[10] += Block128::ONE;
        assert_eq!(
            verify_checkpoint_poseidon(&start, &end, &witness, &proof),
            Err(CheckpointPoseidonError::HeaderFieldMismatch { index: 0 })
        );
    }

    #[test]
    fn checkpoint_poseidon_rejects_chain_claim_tamper() {
        let (start, end, mut witness) = fixture();
        let proof = prove_checkpoint_poseidon(&start, &end, &witness).unwrap();
        witness.accepted_block_claims[1][1] += Block128::ONE;
        assert_eq!(
            verify_checkpoint_poseidon(&start, &end, &witness, &proof),
            Err(CheckpointPoseidonError::ChainAccumulatorProofRejected)
        );
    }
}
