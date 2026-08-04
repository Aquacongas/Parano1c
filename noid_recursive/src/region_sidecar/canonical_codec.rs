// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Length-free canonical codec for fixed-shape HistoryStep sidecars.
//!
//! Every vector dimension comes from an authenticated VK and outer Field
//! shape. No length, option tag, or platform-sized integer is accepted from
//! the wire. Decoders compare the complete byte length before allocating.

use noid_ivc_core::deep_chain::relations::{
    ColumnRelationProof, ShiftDischargeProof, RELATION_DEGREE,
};
use noid_ivc_core::deep_chain::{MultiDeepChainWalkProof, MultiWalkLayerProof, WALK_DEGREE};
use noid_ivc_core::field::F128;
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

use crate::acceptance::trace::region_source_binding::{
    DuplexUnionWalkDeferredProof, MerkleUnionWalkDeferredProof, WalkAUnionWalkDeferredProof,
};

use super::bounded_decode::{
    DeferredFixedProofShape, DeferredMerkleProofShape, MultiWalkProofShape, ProofTailShape,
    RelationShape,
};
use super::RegionSidecarError;

const F128_BYTES: usize = 16;

fn invalid() -> RegionSidecarError {
    RegionSidecarError::InvalidProof
}

fn add(left: usize, right: usize) -> Result<usize, RegionSidecarError> {
    left.checked_add(right).ok_or_else(invalid)
}

fn mul(left: usize, right: usize) -> Result<usize, RegionSidecarError> {
    left.checked_mul(right).ok_or_else(invalid)
}

fn relation_len(shape: RelationShape) -> Result<usize, RegionSidecarError> {
    mul(
        add(mul(shape.rounds, RELATION_DEGREE)?, shape.values)?,
        F128_BYTES,
    )
}

fn shift_len(w_log: usize) -> Result<usize, RegionSidecarError> {
    mul(add(mul(w_log, 2)?, 1)?, F128_BYTES)
}

pub(crate) fn deferred_fixed_len(
    shape: &DeferredFixedProofShape,
) -> Result<usize, RegionSidecarError> {
    let mut len = 1usize;
    len = add(
        len,
        relation_len(RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        })?,
    )?;
    len = add(
        len,
        relation_len(RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        })?,
    )?;
    len = add(len, mul(shape.shifts, shift_len(shape.w_log)?)?)?;
    if let ProofTailShape::RelationOption(Some(tail)) = shape.tail {
        len = add(len, relation_len(tail)?)?;
    }
    Ok(len)
}

pub(crate) fn deferred_merkle_len(
    shape: &DeferredMerkleProofShape,
) -> Result<usize, RegionSidecarError> {
    let relations = [
        RelationShape {
            rounds: shape.w_log,
            values: shape.zero_values,
        },
        RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        },
        RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        },
    ];
    let mut len = 1usize;
    for relation in relations {
        len = add(len, relation_len(relation)?)?;
    }
    len = add(
        len,
        mul(
            add(shape.zero_shifts, shape.shifts)?,
            shift_len(shape.w_log)?,
        )?,
    )?;
    Ok(len)
}

pub(crate) fn multi_walk_len(shape: &MultiWalkProofShape) -> Result<usize, RegionSidecarError> {
    let round_lanes = mul(shape.w_log, WALK_DEGREE)?;
    let next_lanes = mul(shape.instances, STATE_SIZE)?;
    mul(mul(N_ROUNDS, add(round_lanes, next_lanes)?)?, F128_BYTES)
}

pub(crate) struct CanonicalProofReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> CanonicalProofReader<'a> {
    pub(crate) fn exact(bytes: &'a [u8], expected: usize) -> Result<Self, RegionSidecarError> {
        if bytes.len() != expected {
            return Err(invalid());
        }
        Ok(Self { bytes, position: 0 })
    }

    pub(crate) fn finish(self) -> Result<(), RegionSidecarError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }

    pub(crate) fn u8(&mut self) -> Result<u8, RegionSidecarError> {
        let value = *self.bytes.get(self.position).ok_or_else(invalid)?;
        self.position += 1;
        Ok(value)
    }

    pub(crate) fn f128(&mut self) -> Result<F128, RegionSidecarError> {
        let end = add(self.position, F128_BYTES)?;
        let bytes = self.bytes.get(self.position..end).ok_or_else(invalid)?;
        self.position = end;
        Ok(F128 {
            lo: u64::from_le_bytes(bytes[..8].try_into().map_err(|_| invalid())?),
            hi: u64::from_le_bytes(bytes[8..].try_into().map_err(|_| invalid())?),
        })
    }
}

pub(crate) fn put_f128(out: &mut Vec<u8>, value: F128) {
    out.extend_from_slice(&value.lo.to_le_bytes());
    out.extend_from_slice(&value.hi.to_le_bytes());
}

fn encode_relation(
    out: &mut Vec<u8>,
    proof: &ColumnRelationProof,
    shape: RelationShape,
) -> Result<(), RegionSidecarError> {
    if proof.rounds.len() != shape.rounds || proof.final_values.len() != shape.values {
        return Err(invalid());
    }
    for round in &proof.rounds {
        for value in round {
            put_f128(out, *value);
        }
    }
    for value in &proof.final_values {
        put_f128(out, *value);
    }
    Ok(())
}

fn decode_relation(
    reader: &mut CanonicalProofReader<'_>,
    shape: RelationShape,
) -> Result<ColumnRelationProof, RegionSidecarError> {
    let mut rounds = Vec::with_capacity(shape.rounds);
    for _ in 0..shape.rounds {
        let mut round = [F128::ZERO; RELATION_DEGREE];
        for value in &mut round {
            *value = reader.f128()?;
        }
        rounds.push(round);
    }
    let mut final_values = Vec::with_capacity(shape.values);
    for _ in 0..shape.values {
        final_values.push(reader.f128()?);
    }
    Ok(ColumnRelationProof {
        rounds,
        final_values,
    })
}

fn encode_shifts(
    out: &mut Vec<u8>,
    proofs: &[ShiftDischargeProof],
    count: usize,
    w_log: usize,
) -> Result<(), RegionSidecarError> {
    if proofs.len() != count || proofs.iter().any(|proof| proof.rounds.len() != w_log) {
        return Err(invalid());
    }
    for proof in proofs {
        for round in &proof.rounds {
            put_f128(out, round[0]);
            put_f128(out, round[1]);
        }
        put_f128(out, proof.final_value);
    }
    Ok(())
}

fn decode_shifts(
    reader: &mut CanonicalProofReader<'_>,
    count: usize,
    w_log: usize,
) -> Result<Vec<ShiftDischargeProof>, RegionSidecarError> {
    let mut proofs = Vec::with_capacity(count);
    for _ in 0..count {
        let mut rounds = Vec::with_capacity(w_log);
        for _ in 0..w_log {
            rounds.push([reader.f128()?, reader.f128()?]);
        }
        proofs.push(ShiftDischargeProof {
            rounds,
            final_value: reader.f128()?,
        });
    }
    Ok(proofs)
}

pub(crate) fn encode_duplex_deferred(
    out: &mut Vec<u8>,
    version: u8,
    authority: &DuplexUnionWalkDeferredProof,
    shape: &DeferredFixedProofShape,
) -> Result<(), RegionSidecarError> {
    if version != shape.version || !matches!(shape.tail, ProofTailShape::None) {
        return Err(invalid());
    }
    out.push(version);
    encode_relation(
        out,
        &authority.selection,
        RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        },
    )?;
    encode_relation(
        out,
        &authority.substitution,
        RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        },
    )?;
    encode_shifts(out, &authority.shifts, shape.shifts, shape.w_log)
}

pub(crate) fn decode_duplex_deferred(
    reader: &mut CanonicalProofReader<'_>,
    shape: &DeferredFixedProofShape,
) -> Result<DuplexUnionWalkDeferredProof, RegionSidecarError> {
    if reader.u8()? != shape.version || !matches!(shape.tail, ProofTailShape::None) {
        return Err(invalid());
    }
    Ok(DuplexUnionWalkDeferredProof {
        selection: decode_relation(
            reader,
            RelationShape {
                rounds: shape.w_log,
                values: shape.selection_values,
            },
        )?,
        substitution: decode_relation(
            reader,
            RelationShape {
                rounds: shape.w_log,
                values: shape.substitution_values,
            },
        )?,
        shifts: decode_shifts(reader, shape.shifts, shape.w_log)?,
    })
}

pub(crate) fn encode_walk_a_deferred(
    out: &mut Vec<u8>,
    version: u8,
    authority: &WalkAUnionWalkDeferredProof,
    shape: &DeferredFixedProofShape,
) -> Result<(), RegionSidecarError> {
    if version != shape.version {
        return Err(invalid());
    }
    out.push(version);
    encode_relation(
        out,
        &authority.selection,
        RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        },
    )?;
    encode_relation(
        out,
        &authority.substitution,
        RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        },
    )?;
    encode_shifts(out, &authority.shifts, shape.shifts, shape.w_log)?;
    match (shape.tail, authority.spine_exposure.as_ref()) {
        (ProofTailShape::RelationOption(None), None) | (ProofTailShape::None, None) => Ok(()),
        (ProofTailShape::RelationOption(Some(tail)), Some(proof)) => {
            encode_relation(out, proof, tail)
        }
        _ => Err(invalid()),
    }
}

pub(crate) fn decode_walk_a_deferred(
    reader: &mut CanonicalProofReader<'_>,
    shape: &DeferredFixedProofShape,
) -> Result<WalkAUnionWalkDeferredProof, RegionSidecarError> {
    if reader.u8()? != shape.version {
        return Err(invalid());
    }
    let selection = decode_relation(
        reader,
        RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        },
    )?;
    let substitution = decode_relation(
        reader,
        RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        },
    )?;
    let shifts = decode_shifts(reader, shape.shifts, shape.w_log)?;
    let spine_exposure = match shape.tail {
        ProofTailShape::None | ProofTailShape::RelationOption(None) => None,
        ProofTailShape::RelationOption(Some(tail)) => Some(decode_relation(reader, tail)?),
    };
    Ok(WalkAUnionWalkDeferredProof {
        selection,
        substitution,
        shifts,
        spine_exposure,
    })
}

pub(crate) fn encode_merkle_deferred(
    out: &mut Vec<u8>,
    version: u8,
    authority: &MerkleUnionWalkDeferredProof,
    shape: &DeferredMerkleProofShape,
) -> Result<(), RegionSidecarError> {
    if version != shape.version {
        return Err(invalid());
    }
    out.push(version);
    encode_relation(
        out,
        &authority.zero,
        RelationShape {
            rounds: shape.w_log,
            values: shape.zero_values,
        },
    )?;
    encode_shifts(out, &authority.zero_shifts, shape.zero_shifts, shape.w_log)?;
    encode_relation(
        out,
        &authority.selection,
        RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        },
    )?;
    encode_relation(
        out,
        &authority.substitution,
        RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        },
    )?;
    encode_shifts(out, &authority.shifts, shape.shifts, shape.w_log)
}

pub(crate) fn decode_merkle_deferred(
    reader: &mut CanonicalProofReader<'_>,
    shape: &DeferredMerkleProofShape,
) -> Result<MerkleUnionWalkDeferredProof, RegionSidecarError> {
    if reader.u8()? != shape.version {
        return Err(invalid());
    }
    Ok(MerkleUnionWalkDeferredProof {
        zero: decode_relation(
            reader,
            RelationShape {
                rounds: shape.w_log,
                values: shape.zero_values,
            },
        )?,
        zero_shifts: decode_shifts(reader, shape.zero_shifts, shape.w_log)?,
        selection: decode_relation(
            reader,
            RelationShape {
                rounds: shape.w_log,
                values: shape.selection_values,
            },
        )?,
        substitution: decode_relation(
            reader,
            RelationShape {
                rounds: shape.w_log,
                values: shape.substitution_values,
            },
        )?,
        shifts: decode_shifts(reader, shape.shifts, shape.w_log)?,
    })
}

pub(crate) fn encode_multi_walk(
    out: &mut Vec<u8>,
    proof: &MultiDeepChainWalkProof,
    shape: &MultiWalkProofShape,
) -> Result<(), RegionSidecarError> {
    if proof.layers.len() != N_ROUNDS
        || proof.layers.iter().any(|layer| {
            layer.round_coeffs.len() != shape.w_log || layer.next_values.len() != shape.instances
        })
    {
        return Err(invalid());
    }
    for layer in &proof.layers {
        for round in &layer.round_coeffs {
            for value in round {
                put_f128(out, *value);
            }
        }
        for next in &layer.next_values {
            for value in next {
                put_f128(out, *value);
            }
        }
    }
    Ok(())
}

pub(crate) fn decode_multi_walk(
    reader: &mut CanonicalProofReader<'_>,
    shape: &MultiWalkProofShape,
) -> Result<MultiDeepChainWalkProof, RegionSidecarError> {
    let mut layers = Vec::with_capacity(N_ROUNDS);
    for _ in 0..N_ROUNDS {
        let mut round_coeffs = Vec::with_capacity(shape.w_log);
        for _ in 0..shape.w_log {
            let mut round = [F128::ZERO; WALK_DEGREE];
            for value in &mut round {
                *value = reader.f128()?;
            }
            round_coeffs.push(round);
        }
        let mut next_values = Vec::with_capacity(shape.instances);
        for _ in 0..shape.instances {
            let mut next = [F128::ZERO; STATE_SIZE];
            for value in &mut next {
                *value = reader.f128()?;
            }
            next_values.push(next);
        }
        layers.push(MultiWalkLayerProof {
            round_coeffs,
            next_values,
        });
    }
    Ok(MultiDeepChainWalkProof { layers })
}
