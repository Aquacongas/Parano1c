// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Header-hash proof component for the Poseidon2b-heavy recursive path.
//!
//! This module contains the proof object for the parts of a checkpoint batch
//! that are already arithmetic and KillShot-native:
//!
//! - canonical semantic-header and PoW-header Poseidon2b hashing.
//!
//! It is a subrelation of the public checkpoint path. Header integer rules and
//! the full block-validity relation are handled by separate proof obligations.

use noid_chain::consensus::pow::pow_header_fields;
use noid_gkr::{
    discharge_header_hash_reductions_native_padded, prove_header_hash_killshot_padded,
    verify_header_hash_killshot_padded, HeaderHashProofKillShot,
};
use noid_poseidon2b::channel::Poseidon2bChannel;

use crate::accepted_batch::AcceptedClaimBatchWitness;
use crate::pow_header::header_hash_proof_inputs;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointPoseidonProof {
    pub header_hash: HeaderHashProofKillShot,
    pub n_blocks: usize,
}

impl CheckpointPoseidonProof {
    pub fn byte_len(&self) -> usize {
        self.header_hash.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointPoseidonError {
    EmptyBatch,
    ClaimCountMismatch { headers: usize, claims: usize },
    HeaderFieldMismatch { index: usize },
    HeaderTargetMismatch { index: usize },
    HeaderHashProofRejected,
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

/// Build the header-hash checkpoint component proof.
///
/// The caller must separately prove or verify header integer consensus and the
/// full accepted-block relation before treating this checkpoint as authority.
pub fn prove_checkpoint_poseidon(
    witness: &AcceptedClaimBatchWitness,
) -> Result<CheckpointPoseidonProof, CheckpointPoseidonError> {
    prove_checkpoint_poseidon_padded(witness, witness.headers.len())
}

/// Build the Poseidon2b checkpoint component proof with a fixed proof shape.
///
/// `padded_blocks` fixes the underlying permutation-spine size. Extra
/// permutation slots are independent padding witnesses, so the public
/// checkpoint statement remains exactly the supplied `witness`.
pub fn prove_checkpoint_poseidon_padded(
    witness: &AcceptedClaimBatchWitness,
    padded_blocks: usize,
) -> Result<CheckpointPoseidonProof, CheckpointPoseidonError> {
    validate_shape(witness)?;
    if witness.headers.len() > padded_blocks {
        return Err(CheckpointPoseidonError::ClaimCountMismatch {
            headers: witness.headers.len(),
            claims: padded_blocks,
        });
    }

    let header_inputs = header_hash_proof_inputs(&witness.headers);
    let mut channel = Poseidon2bChannel::new();
    let header_hash =
        prove_header_hash_killshot_padded(&header_inputs, padded_blocks, &mut channel).0;

    Ok(CheckpointPoseidonProof {
        header_hash,
        n_blocks: witness.headers.len(),
    })
}

/// Verify the Poseidon2b checkpoint component proof.
///
/// This verifier checks no native Poseidon2b digests. The header hash proof
/// binds the supplied canonical field schedule to `pow_digest` and `block_id`.
/// Direct accumulator continuity is a separate arithmetic relation.
pub fn verify_checkpoint_poseidon(
    witness: &AcceptedClaimBatchWitness,
    proof: &CheckpointPoseidonProof,
) -> Result<(), CheckpointPoseidonError> {
    verify_checkpoint_poseidon_padded(witness, proof, witness.headers.len())
}

/// Verify a Poseidon2b checkpoint proof whose underlying spine was padded to a
/// fixed number of blocks.
pub fn verify_checkpoint_poseidon_padded(
    witness: &AcceptedClaimBatchWitness,
    proof: &CheckpointPoseidonProof,
    padded_blocks: usize,
) -> Result<(), CheckpointPoseidonError> {
    validate_shape(witness)?;
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
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_header_hash_killshot_padded(
        &proof.header_hash,
        &header_inputs,
        padded_blocks,
        &mut channel,
    )
    .ok_or(CheckpointPoseidonError::HeaderHashProofRejected)?;
    if discharge_header_hash_reductions_native_padded(&header_inputs, &reductions, padded_blocks) {
        Ok(())
    } else {
        Err(CheckpointPoseidonError::HeaderHashProofRejected)
    }
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
            attested_coverage: 0,
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

    fn fixture_n(n: usize) -> AcceptedClaimBatchWitness {
        assert!(n > 0);
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
            prev_block_id = w.block_id;
            headers.push(w);
            claims.push(claim);
        }

        AcceptedClaimBatchWitness {
            headers,
            accepted_block_claims: claims,
        }
    }

    fn fixture() -> AcceptedClaimBatchWitness {
        fixture_n(2)
    }

    #[test]
    fn checkpoint_poseidon_roundtrip() {
        let witness = fixture();
        let proof = prove_checkpoint_poseidon(&witness).unwrap();
        verify_checkpoint_poseidon(&witness, &proof).unwrap();
        assert!(proof.byte_len() > 0);
    }

    #[test]
    fn checkpoint_poseidon_padded_roundtrip_size_constant_and_rejects_small_shape() {
        let padded_blocks = 4;
        let mut expected_len = None;

        for n in [1usize, 2, padded_blocks] {
            let witness = fixture_n(n);
            let proof = prove_checkpoint_poseidon_padded(&witness, padded_blocks).unwrap();
            verify_checkpoint_poseidon_padded(&witness, &proof, padded_blocks).unwrap();
            assert_eq!(proof.n_blocks, n);

            if let Some(expected_len) = expected_len {
                assert_eq!(proof.byte_len(), expected_len);
            } else {
                expected_len = Some(proof.byte_len());
            }

            if n < padded_blocks {
                assert_eq!(
                    verify_checkpoint_poseidon_padded(&witness, &proof, n),
                    Err(CheckpointPoseidonError::HeaderHashProofRejected)
                );
            }
        }

        let witness = fixture_n(1);
        let small_shape_proof = prove_checkpoint_poseidon(&witness).unwrap();
        assert_eq!(
            verify_checkpoint_poseidon_padded(&witness, &small_shape_proof, padded_blocks),
            Err(CheckpointPoseidonError::HeaderHashProofRejected)
        );
    }

    #[test]
    fn checkpoint_poseidon_rejects_header_field_split() {
        let mut witness = fixture();
        let proof = prove_checkpoint_poseidon(&witness).unwrap();
        witness.headers[0].pow_fields[10] += Block128::ONE;
        assert_eq!(
            verify_checkpoint_poseidon(&witness, &proof),
            Err(CheckpointPoseidonError::HeaderFieldMismatch { index: 0 })
        );
    }

    #[test]
    fn checkpoint_poseidon_rejects_block_id_tamper() {
        let mut witness = fixture();
        let proof = prove_checkpoint_poseidon(&witness).unwrap();
        witness.headers[1].block_id[17] ^= 1;
        assert_eq!(
            verify_checkpoint_poseidon(&witness, &proof),
            Err(CheckpointPoseidonError::HeaderHashProofRejected)
        );
    }

    #[test]
    fn checkpoint_poseidon_claims_are_shape_only() {
        let mut witness = fixture_n(2);
        let proof = prove_checkpoint_poseidon_padded(&witness, 4).unwrap();
        witness.accepted_block_claims[1][1] += Block128::ONE;
        verify_checkpoint_poseidon_padded(&witness, &proof, 4).unwrap();
    }
}
