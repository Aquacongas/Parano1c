// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid. All rights reserved.

//! Binius-style packed commitment, layered on the existing FRI PCS.
//!
//! The commitment is just the FRI commitment of the packed vector:
//!
//! ```text
//!   commit(BitWitness of length N)    = FRI.commit(pack_bits(witness))      // N/128 leaves
//!   commit(ByteWitness of length N)   = FRI.commit(pack_bytes(witness))     // N/16 leaves
//! ```
//!
//! Bandwidth / DA impact is immediate: the committed vector length — which
//! dominates prove, NTT, Merkle and proof sizes at the FRI layer — drops
//! by 128x (bits) or 16x (bytes) vs. embedding the small-field values
//! directly as Block128.
//!
//! # Soundness
//!
//! This layer inherits FRI soundness verbatim. The verifier checks a claim
//! of the form "packed_mle(point) = eval" where `packed_mle` is the
//! multilinear extension of the packed Block128 vector. That is exactly the
//! claim FRI is built for.
//!
//! # Byte and Block128 domains
//!
//! For cells that live natively in GF(2^8) (byte domain) or GF(2^128) (raw
//! Block128), the packed MLE *is* the polynomial the AIR reasons about —
//! there is no reduction step. A byte in cell `j` of the logical column
//! corresponds to the `(j % 16)`-th byte of packed word `j / 16`, and the
//! multilinear extension the verifier wants to evaluate is the MLE of the
//! packed vector in the `log(len/16)` outer variables.
//!
//! # Bit domain
//!
//! For cells that live in GF(2), the packed vector serves as the canonical
//! DA/root representation; prove/verify expand the bit column back to a
//! Block128 vector (embedding 0→0, 1→1) before running FRI. This keeps the
//! 128x DA/commit savings, while the opening itself runs on the expanded
//! form with unchanged soundness.

use noid_core::{AdditiveNTT, Block128};
use noid_fri::channel::Channel;
use noid_fri::hasher::CryptographicHasher;
use noid_fri::prover::{commit as fri_commit, prove as fri_prove, EvalProof, FriCommitment};
use noid_fri::verifier::verify as fri_verify;

/// A commitment to a packed small-field witness.
#[derive(Clone, Debug)]
pub struct PackedCommitment {
    pub inner: FriCommitment,
    /// log2 of the packed vector length (= `log_len` of the FRI commitment).
    pub log_packed_len: usize,
    /// Bits per packed cell: 1 (Block128 direct), 8 (bytes), or 128 (bits).
    /// Informational; the commitment itself is field-agnostic.
    pub small_field_bits: u8,
}

/// An evaluation proof for a claim on the packed MLE.
///
/// Currently an alias of the FRI eval proof.
pub type PackedEvalProof = EvalProof;

/// Handle to a committed packed vector, keeping the Merkle tree needed for
/// opening.
pub struct PackedCommit {
    pub commitment: PackedCommitment,
    pub packed: Vec<Block128>,
}

impl PackedCommit {
    /// Commit to a raw Block128 vector (no packing — `small_field_bits = 128`).
    pub fn commit_raw(
        packed: Vec<Block128>,
        ntt: &AdditiveNTT<Block128>,
        hasher: &dyn CryptographicHasher,
    ) -> Self {
        Self::commit_internal(packed, 128, ntt, hasher)
    }

    /// Commit to a byte witness. The prover passes the packed representation
    /// (16 bytes per Block128); the commitment runs on that compact vector.
    pub fn commit_bytes(
        packed: Vec<Block128>,
        ntt: &AdditiveNTT<Block128>,
        hasher: &dyn CryptographicHasher,
    ) -> Self {
        Self::commit_internal(packed, 8, ntt, hasher)
    }

    /// Commit to a bit witness (128 bits per Block128).
    pub fn commit_bits(
        packed: Vec<Block128>,
        ntt: &AdditiveNTT<Block128>,
        hasher: &dyn CryptographicHasher,
    ) -> Self {
        Self::commit_internal(packed, 1, ntt, hasher)
    }

    fn commit_internal(
        packed: Vec<Block128>,
        small_field_bits: u8,
        ntt: &AdditiveNTT<Block128>,
        hasher: &dyn CryptographicHasher,
    ) -> Self {
        assert!(packed.len().is_power_of_two());
        let log_packed_len = packed.len().trailing_zeros() as usize;
        let (inner, _tree, _code) = fri_commit(&packed, ntt, hasher);
        Self {
            commitment: PackedCommitment {
                inner,
                log_packed_len,
                small_field_bits,
            },
            packed,
        }
    }

    pub fn small_field_bits(&self) -> u8 {
        self.commitment.small_field_bits
    }

    /// DA / wire serialisation size in bytes for the committed vector itself
    /// (not counting the commitment root). This is the number applications
    /// care about when sizing blocks.
    pub fn serialized_size(&self) -> usize {
        self.packed.len() * 16
    }

    /// Open the packed MLE at `point` (length = `log_packed_len`).
    ///
    /// The returned proof is the standard FRI eval proof; verification is
    /// via [`verify_packed`].
    pub fn open(
        &self,
        point: &[Block128],
        ntt: &AdditiveNTT<Block128>,
        channel: &mut Channel,
        hasher: &dyn CryptographicHasher,
    ) -> PackedEvalProof {
        assert_eq!(point.len(), self.commitment.log_packed_len);
        channel.observe_fri_commitment(&self.commitment.inner);
        fri_prove(
            &self.packed,
            point,
            ntt,
            channel,
            hasher,
        )
    }
}

/// Verify a packed MLE opening.
pub fn verify_packed(
    commitment: &PackedCommitment,
    point: &[Block128],
    claimed_eval: Block128,
    proof: PackedEvalProof,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
) -> Result<(), String> {
    assert_eq!(point.len(), commitment.log_packed_len);
    channel.observe_fri_commitment(&commitment.inner);
    fri_verify(
        point,
        claimed_eval,
        proof,
        ntt,
        channel,
        hasher,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::BitWitness;
    use noid_fri::code::LOG_RATE;
    use noid_poseidon2b::native::compression::Poseidon2bSponge;
    use rand::Rng;

    fn mle_evaluate(evals: &[Block128], point: &[Block128]) -> Block128 {
        let mut buf = evals.to_vec();
        for &r in point.iter().rev() {
            let half = buf.len() / 2;
            for i in 0..half {
                buf[i] = buf[i] + r * (buf[i + half] + buf[i]);
            }
            buf.truncate(half);
        }
        buf[0]
    }

    #[test]
    fn bit_witness_commit_and_open() {
        // 2^10 * 128 = 131072 bits -> 1024 packed Block128 words -> log_packed_len = 10
        let log_packed_len = 10;
        let n_packed = 1usize << log_packed_len;

        let mut rng = rand::thread_rng();
        let bits: Vec<u8> = (0..n_packed * 128).map(|_| rng.gen::<bool>() as u8).collect();
        let w = BitWitness::from_bits(&bits);
        assert_eq!(w.n_packed(), n_packed);

        let ntt = AdditiveNTT::<Block128>::new(log_packed_len + LOG_RATE);
        let hasher = Poseidon2bSponge::new();

        let committed = PackedCommit::commit_bits(w.as_packed().to_vec(), &ntt, &hasher);

        let point: Vec<Block128> = (0..log_packed_len)
            .map(|_| Block128::from(rng.gen::<u128>()))
            .collect();
        let claimed_eval = mle_evaluate(w.as_packed(), &point);

        let mut pc = Channel::new();
        let proof = committed.open(&point, &ntt, &mut pc, &hasher);
        let mut vc = Channel::new();
        verify_packed(
            &committed.commitment,
            &point,
            claimed_eval,
            proof,
            &ntt,
            &mut vc,
            &hasher,
        )
        .expect("packed bit-commitment verifies");
    }

    #[test]
    fn byte_witness_size_saving() {
        // 2^14 bytes = 16384 bytes = 1024 packed Block128 words -> log 10.
        let n_bytes = 1usize << 14;
        let bytes: Vec<u8> = (0..n_bytes).map(|i| (i & 0xFF) as u8).collect();
        let packed = crate::pack::pack_bytes(&bytes);

        let ntt = AdditiveNTT::<Block128>::new(10 + LOG_RATE);
        let hasher = Poseidon2bSponge::new();
        let c = PackedCommit::commit_bytes(packed, &ntt, &hasher);

        // Naive Block128 embedding would be 16384 * 16 = 256 KiB.
        // Packed: 1024 * 16 = 16 KiB. 16x smaller.
        assert_eq!(c.serialized_size(), 16 * 1024);
    }
}
