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
    discharge_chain_accumulator_reductions_native_padded,
    discharge_header_hash_reductions_native_padded, prove_chain_accumulator_killshot_padded,
    prove_header_hash_killshot_padded, verify_chain_accumulator_killshot_padded,
    verify_header_hash_killshot_padded, ChainAccumulatorProofKillShot, HeaderHashProofKillShot,
};
use noid_poseidon2b::channel::Poseidon2bChannel;

use crate::accepted_batch::{chain_accumulator_proof_inputs, AcceptedClaimBatchWitness};
use crate::accumulator::ChainAccumulator;
use crate::pow_header::header_hash_proof_inputs;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    prove_checkpoint_poseidon_padded(
        start_accumulator,
        end_accumulator,
        witness,
        witness.headers.len(),
    )
}

/// Build the Poseidon2b checkpoint component proof with a fixed proof shape.
///
/// `padded_blocks` fixes the underlying permutation-spine size. Extra
/// permutation slots are independent padding witnesses and are not accumulator
/// rows, so the public checkpoint statement remains exactly the supplied
/// `witness` and accumulator boundary.
pub fn prove_checkpoint_poseidon_padded(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    witness: &AcceptedClaimBatchWitness,
    padded_blocks: usize,
) -> Result<CheckpointPoseidonProof, CheckpointPoseidonError> {
    validate_shape(witness)?;
    validate_accumulator_boundary(start_accumulator, end_accumulator, witness)?;
    if witness.headers.len() > padded_blocks {
        return Err(CheckpointPoseidonError::ClaimCountMismatch {
            headers: witness.headers.len(),
            claims: padded_blocks,
        });
    }

    let header_inputs = header_hash_proof_inputs(&witness.headers);
    let chain_inputs = chain_accumulator_proof_inputs(start_accumulator, witness, end_accumulator);
    let (header_hash, chain_accumulator) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            prove_header_hash_killshot_padded(&header_inputs, padded_blocks, &mut channel).0
        },
        || {
            let mut channel = Poseidon2bChannel::new();
            prove_chain_accumulator_killshot_padded(&chain_inputs, padded_blocks, &mut channel).0
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
    verify_checkpoint_poseidon_padded(
        start_accumulator,
        end_accumulator,
        witness,
        proof,
        witness.headers.len(),
    )
}

/// Verify a Poseidon2b checkpoint proof whose underlying spine was padded to a
/// fixed number of blocks.
pub fn verify_checkpoint_poseidon_padded(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    witness: &AcceptedClaimBatchWitness,
    proof: &CheckpointPoseidonProof,
    padded_blocks: usize,
) -> Result<(), CheckpointPoseidonError> {
    validate_shape(witness)?;
    validate_accumulator_boundary(start_accumulator, end_accumulator, witness)?;
    if proof.n_blocks != witness.headers.len() {
        return Err(CheckpointPoseidonError::ClaimCountMismatch {
            headers: proof.n_blocks,
            claims: witness.headers.len(),
        });
    }
    if witness.headers.len() > padded_blocks {
        return Err(CheckpointPoseidonError::ClaimCountMismatch {
            headers: witness.headers.len(),
            claims: padded_blocks,
        });
    }

    let header_inputs = header_hash_proof_inputs(&witness.headers);
    let chain_inputs = chain_accumulator_proof_inputs(start_accumulator, witness, end_accumulator);
    let (header_result, chain_result) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            let reductions = verify_header_hash_killshot_padded(
                &proof.header_hash,
                &header_inputs,
                padded_blocks,
                &mut channel,
            )
            .ok_or(CheckpointPoseidonError::HeaderHashProofRejected)?;
            if discharge_header_hash_reductions_native_padded(
                &header_inputs,
                &reductions,
                padded_blocks,
            ) {
                Ok(())
            } else {
                Err(CheckpointPoseidonError::HeaderHashProofRejected)
            }
        },
        || {
            let mut channel = Poseidon2bChannel::new();
            let reductions = verify_chain_accumulator_killshot_padded(
                &proof.chain_accumulator,
                &chain_inputs,
                padded_blocks,
                &mut channel,
            )
            .ok_or(CheckpointPoseidonError::ChainAccumulatorProofRejected)?;
            if discharge_chain_accumulator_reductions_native_padded(
                &chain_inputs,
                &reductions,
                padded_blocks,
            ) {
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

    fn fixture_n(
        n: usize,
    ) -> (
        ChainAccumulator,
        ChainAccumulator,
        AcceptedClaimBatchWitness,
    ) {
        assert!(n > 0);
        let start = ChainAccumulator {
            height: 0,
            state_root: [1u8; 32],
            chain_hash: [0u8; 32],
        };
        let mut acc = start.clone();
        let mut prev_block_id = [0u8; 32];
        let mut headers = Vec::with_capacity(n);
        let mut claims = Vec::with_capacity(n);

        for height in 1..=n as u64 {
            let h = header(height, prev_block_id, height as u8 + 1);
            let w = HeaderWitness::from_header(&h);
            let claim = [
                Block128::from(0xA0u128 + height as u128),
                Block128::from(0xB0u128 + height as u128),
            ];
            acc = acc.extend(h.state_root, w.block_id, h.height, claim);
            prev_block_id = w.block_id;
            headers.push(w);
            claims.push(claim);
        }

        let witness = AcceptedClaimBatchWitness {
            headers,
            accepted_block_claims: claims,
        };
        (start, acc, witness)
    }

    fn fixture() -> (
        ChainAccumulator,
        ChainAccumulator,
        AcceptedClaimBatchWitness,
    ) {
        fixture_n(2)
    }

    #[test]
    fn checkpoint_poseidon_roundtrip() {
        let (start, end, witness) = fixture();
        let proof = prove_checkpoint_poseidon(&start, &end, &witness).unwrap();
        verify_checkpoint_poseidon(&start, &end, &witness, &proof).unwrap();
        assert!(proof.byte_len() > 0);
    }

    #[test]
    fn checkpoint_poseidon_padded_roundtrip_size_constant_and_rejects_small_shape() {
        let padded_blocks = 4;
        let mut expected_len = None;

        for n in [1usize, 2, padded_blocks] {
            let (start, end, witness) = fixture_n(n);
            let proof =
                prove_checkpoint_poseidon_padded(&start, &end, &witness, padded_blocks).unwrap();
            verify_checkpoint_poseidon_padded(&start, &end, &witness, &proof, padded_blocks)
                .unwrap();
            assert_eq!(proof.n_blocks, n);

            if let Some(expected_len) = expected_len {
                assert_eq!(proof.byte_len(), expected_len);
            } else {
                expected_len = Some(proof.byte_len());
            }

            if n < padded_blocks {
                assert_eq!(
                    verify_checkpoint_poseidon_padded(&start, &end, &witness, &proof, n),
                    Err(CheckpointPoseidonError::HeaderHashProofRejected)
                );
            }
        }

        let (start, end, witness) = fixture_n(1);
        let small_shape_proof = prove_checkpoint_poseidon(&start, &end, &witness).unwrap();
        assert_eq!(
            verify_checkpoint_poseidon_padded(
                &start,
                &end,
                &witness,
                &small_shape_proof,
                padded_blocks,
            ),
            Err(CheckpointPoseidonError::HeaderHashProofRejected)
        );
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

    #[test]
    fn checkpoint_poseidon_rejects_end_chain_hash_tamper_under_padding() {
        let (start, mut end, witness) = fixture_n(2);
        let proof = prove_checkpoint_poseidon_padded(&start, &end, &witness, 4).unwrap();
        end.chain_hash[0] ^= 1;
        assert_eq!(
            verify_checkpoint_poseidon_padded(&start, &end, &witness, &proof, 4),
            Err(CheckpointPoseidonError::ChainAccumulatorProofRejected)
        );
    }
}
