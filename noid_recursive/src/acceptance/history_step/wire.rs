// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical v1 terminal wire codec.
//!
//! Prefix (42 bytes): `version:u8 || height:u64-le || semantic_id:[u8;32] ||
//! class_id:u8`. The remaining proof shape is derived entirely from the
//! authenticated class/runtime. No vector lengths or serde representation
//! occur on this wire.

use noid_ivc_core::field::{F128, F256};
use noid_ivc_core::pcs::basefold::{C1QueryOpening, C1RoundMessage};
use noid_ivc_core::pcs::{
    compute_fri_arities, default_fri_queries, fri_commit_layout, C1BaseFoldProof, Commitment,
    PcsParams, RoundCommitment, LOG_PACKING,
};
use noid_ivc_core::proof::{C1FieldR1csProof, FieldShape};

use super::relation::{validate_terminal_metadata, verify_history_step_terminal, HistoryStepProof};
use super::*;
use crate::acceptance::history_step_bank::{
    history_step_bank_block_accumulator, CanonicalHistoryStepClassId, HISTORY_STEP_CLASS_COUNT,
};
use crate::region_sidecar::{
    canonical_joint_c1_region_sidecar_len, decode_joint_c1_region_sidecar_canonical,
    encode_joint_c1_region_sidecar_canonical,
};

const PREFIX_BYTES: usize = 42;
const HASH_BYTES: usize = 32;
const F128_BYTES: usize = 16;
const F256_BYTES: usize = 32;

fn add(left: usize, right: usize) -> Result<usize, HistoryStepError> {
    left.checked_add(right)
        .ok_or(HistoryStepError::WireEncoding)
}

fn mul(left: usize, right: usize) -> Result<usize, HistoryStepError> {
    left.checked_mul(right)
        .ok_or(HistoryStepError::WireEncoding)
}

#[derive(Clone, Debug)]
struct BaseFoldWireShape {
    round_messages: usize,
    round_commitments: usize,
    final_codeword: usize,
    plaintext_tail: usize,
    queries: usize,
    initial_leaf: usize,
    initial_path: usize,
    post_row_batch_leaf: usize,
    post_row_batch_path: usize,
    epoch_shapes: Vec<(usize, usize)>,
}

impl BaseFoldWireShape {
    fn derive(params: &PcsParams) -> Result<Self, HistoryStepError> {
        let log_msg_len = params
            .m
            .checked_sub(LOG_PACKING)
            .ok_or(HistoryStepError::WireEncoding)?;
        let log_dim = log_msg_len
            .checked_sub(params.log_batch_size)
            .ok_or(HistoryStepError::WireEncoding)?;
        let k_code = log_dim
            .checked_add(params.log_inv_rate)
            .ok_or(HistoryStepError::WireEncoding)?;
        if k_code >= usize::BITS as usize
            || params.log_batch_size >= usize::BITS as usize
            || params.log_inv_rate >= usize::BITS as usize
        {
            return Err(HistoryStepError::WireEncoding);
        }
        let arities = compute_fri_arities(log_dim);
        let (round_commitments, tail_layout) = fri_commit_layout(k_code, &arities);
        let first_arity = arities.first().copied();
        let mut consumed = first_arity.unwrap_or(0);
        let mut epoch_shapes = Vec::with_capacity(round_commitments);
        for index in 0..round_commitments {
            let arity = *arities
                .get(index + 1)
                .ok_or(HistoryStepError::WireEncoding)?;
            consumed = consumed
                .checked_add(arity)
                .ok_or(HistoryStepError::WireEncoding)?;
            let depth = k_code
                .checked_sub(consumed)
                .ok_or(HistoryStepError::WireEncoding)?;
            epoch_shapes.push((1usize << arity, depth));
        }
        Ok(Self {
            round_messages: log_msg_len,
            round_commitments,
            final_codeword: 1usize << params.log_inv_rate,
            plaintext_tail: tail_layout.map_or(0, |(len, _)| len),
            queries: default_fri_queries(params.log_dim(), params.log_inv_rate),
            initial_leaf: 1usize << params.log_batch_size,
            initial_path: k_code,
            post_row_batch_leaf: first_arity.map_or(0, |arity| 1usize << arity),
            post_row_batch_path: first_arity.map_or(0, |arity| k_code - arity),
            epoch_shapes,
        })
    }

    fn query_encoded_len(&self) -> Result<usize, HistoryStepError> {
        let mut query_len = 8usize;
        query_len = add(query_len, mul(self.initial_leaf, F128_BYTES)?)?;
        query_len = add(query_len, mul(self.initial_path, HASH_BYTES)?)?;
        query_len = add(query_len, mul(self.post_row_batch_leaf, F256_BYTES)?)?;
        query_len = add(query_len, mul(self.post_row_batch_path, HASH_BYTES)?)?;
        for (leaf, path) in &self.epoch_shapes {
            query_len = add(query_len, mul(*leaf, F256_BYTES)?)?;
            query_len = add(query_len, mul(*path, HASH_BYTES)?)?;
        }
        Ok(query_len)
    }

    fn encoded_len(&self) -> Result<usize, HistoryStepError> {
        let mut len = mul(self.round_messages, 2 * F256_BYTES)?;
        len = add(len, HASH_BYTES)?;
        len = add(len, mul(self.round_commitments, HASH_BYTES)?)?;
        len = add(len, 2 * F256_BYTES)?;
        len = add(len, mul(self.final_codeword, F256_BYTES)?)?;
        len = add(len, mul(self.plaintext_tail, F256_BYTES)?)?;
        len = add(len, 8)?;
        add(len, mul(self.queries, self.query_encoded_len()?)?)
    }
}

fn field_proof_len(shape: FieldShape, params: &PcsParams) -> Result<usize, HistoryStepError> {
    if shape.k_skip >= usize::BITS as usize || shape.m < shape.k_skip || shape.k_log < shape.k_skip
    {
        return Err(HistoryStepError::WireEncoding);
    }
    let skip = 1usize << shape.k_skip;
    let zerocheck_lanes = add(add(mul(skip, 2)?, mul(shape.m - shape.k_skip, 2)?)?, 3)?;
    let lincheck_lanes = add(mul(shape.k_log - shape.k_skip, 2)?, skip)?;
    let basefold = BaseFoldWireShape::derive(params)?.encoded_len()?;
    add(
        mul(add(zerocheck_lanes, lincheck_lanes)?, F256_BYTES)?,
        basefold,
    )
}

fn terminal_len_for_class(
    runtime: &HistoryStepRuntime,
    class: CanonicalHistoryStepClassId,
) -> Result<usize, HistoryStepError> {
    let entry = runtime.bank().entry(class);
    let mut len = PREFIX_BYTES;
    len = add(len, HASH_BYTES)?;
    len = add(len, mul(runtime.bank().spec().io_len, F128_BYTES)?)?;
    len = add(len, field_proof_len(entry.shape(), entry.pcs_params())?)?;
    len = add(
        len,
        canonical_joint_c1_region_sidecar_len(
            runtime.parent_recursion_vk(),
            runtime
                .direct_block_vk(class.current_slot())
                .ok_or(HistoryStepError::RuntimeBlockVk(class.current_slot()))?,
            entry.shape().m,
        )?,
    )?;
    Ok(len)
}

pub fn history_step_terminal_max_wire_bytes(
    runtime: &HistoryStepRuntime,
) -> Result<usize, HistoryStepError> {
    (0..HISTORY_STEP_CLASS_COUNT).try_fold(0usize, |maximum, index| {
        let class =
            CanonicalHistoryStepClassId::from_index(index).ok_or(HistoryStepError::InvalidClass)?;
        Ok(maximum.max(terminal_len_for_class(runtime, class)?))
    })
}

fn put_f128(out: &mut Vec<u8>, value: F128) {
    out.extend_from_slice(&value.lo.to_le_bytes());
    out.extend_from_slice(&value.hi.to_le_bytes());
}

fn put_f256(out: &mut Vec<u8>, value: F256) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_hash(out: &mut Vec<u8>, value: &[u8; HASH_BYTES]) {
    out.extend_from_slice(value);
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], HistoryStepError> {
        let end = add(self.position, count)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(HistoryStepError::WireEncoding)?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, HistoryStepError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(HistoryStepError::WireEncoding)?)
    }

    fn u64(&mut self) -> Result<u64, HistoryStepError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| HistoryStepError::WireEncoding)?,
        ))
    }

    fn f128(&mut self) -> Result<F128, HistoryStepError> {
        let bytes = self.take(F128_BYTES)?;
        Ok(F128 {
            lo: u64::from_le_bytes(
                bytes[..8]
                    .try_into()
                    .map_err(|_| HistoryStepError::WireEncoding)?,
            ),
            hi: u64::from_le_bytes(
                bytes[8..]
                    .try_into()
                    .map_err(|_| HistoryStepError::WireEncoding)?,
            ),
        })
    }

    fn f256(&mut self) -> Result<F256, HistoryStepError> {
        let bytes: [u8; F256_BYTES] = self
            .take(F256_BYTES)?
            .try_into()
            .map_err(|_| HistoryStepError::WireEncoding)?;
        Ok(F256::from_le_bytes(bytes))
    }

    fn hash(&mut self) -> Result<[u8; HASH_BYTES], HistoryStepError> {
        self.take(HASH_BYTES)?
            .try_into()
            .map_err(|_| HistoryStepError::WireEncoding)
    }

    fn finish(self) -> Result<(), HistoryStepError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(HistoryStepError::WireEncoding)
        }
    }
}

fn encode_f128_vec(
    out: &mut Vec<u8>,
    values: &[F128],
    expected: usize,
) -> Result<(), HistoryStepError> {
    if values.len() != expected {
        return Err(HistoryStepError::WireEncoding);
    }
    for value in values {
        put_f128(out, *value);
    }
    Ok(())
}

fn decode_f128_vec(reader: &mut Reader<'_>, count: usize) -> Result<Vec<F128>, HistoryStepError> {
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.f128()?);
    }
    Ok(values)
}

fn encode_f256_pair_vec(
    out: &mut Vec<u8>,
    values: &[(F256, F256)],
    expected: usize,
) -> Result<(), HistoryStepError> {
    if values.len() != expected {
        return Err(HistoryStepError::WireEncoding);
    }
    for &(left, right) in values {
        put_f256(out, left);
        put_f256(out, right);
    }
    Ok(())
}

fn decode_f256_pair_vec(
    reader: &mut Reader<'_>,
    count: usize,
) -> Result<Vec<(F256, F256)>, HistoryStepError> {
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push((reader.f256()?, reader.f256()?));
    }
    Ok(values)
}

fn encode_f256_vec(
    out: &mut Vec<u8>,
    values: &[F256],
    expected: usize,
) -> Result<(), HistoryStepError> {
    if values.len() != expected {
        return Err(HistoryStepError::WireEncoding);
    }
    for &value in values {
        put_f256(out, value);
    }
    Ok(())
}

fn decode_f256_vec(reader: &mut Reader<'_>, count: usize) -> Result<Vec<F256>, HistoryStepError> {
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.f256()?);
    }
    Ok(values)
}

fn encode_hash_vec(
    out: &mut Vec<u8>,
    values: &[[u8; HASH_BYTES]],
    expected: usize,
) -> Result<(), HistoryStepError> {
    if values.len() != expected {
        return Err(HistoryStepError::WireEncoding);
    }
    for value in values {
        put_hash(out, value);
    }
    Ok(())
}

fn decode_hash_vec(
    reader: &mut Reader<'_>,
    count: usize,
) -> Result<Vec<[u8; HASH_BYTES]>, HistoryStepError> {
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.hash()?);
    }
    Ok(values)
}

fn encode_field_proof(
    out: &mut Vec<u8>,
    proof: &C1FieldR1csProof,
    shape: FieldShape,
    params: &PcsParams,
) -> Result<(), HistoryStepError> {
    let skip = 1usize << shape.k_skip;
    encode_f256_vec(out, &proof.zerocheck.round1_ab, skip)?;
    encode_f256_vec(out, &proof.zerocheck.round1_c, skip)?;
    encode_f256_pair_vec(
        out,
        &proof.zerocheck.multilinear_rounds,
        shape.m - shape.k_skip,
    )?;
    put_f256(out, proof.zerocheck.final_a_eval);
    put_f256(out, proof.zerocheck.final_b_eval);
    put_f256(out, proof.zerocheck.final_c_eval);
    encode_f256_pair_vec(out, &proof.lincheck.rounds, shape.k_log - shape.k_skip)?;
    encode_f256_vec(out, &proof.lincheck.z_partial, skip)?;
    encode_basefold(out, &proof.pcs_open, &BaseFoldWireShape::derive(params)?)
}

fn decode_field_proof(
    reader: &mut Reader<'_>,
    shape: FieldShape,
    params: &PcsParams,
) -> Result<C1FieldR1csProof, HistoryStepError> {
    let skip = 1usize << shape.k_skip;
    let zerocheck = noid_ivc_core::zerocheck::field_c1::C1ZerocheckProof {
        round1_ab: decode_f256_vec(reader, skip)?,
        round1_c: decode_f256_vec(reader, skip)?,
        multilinear_rounds: decode_f256_pair_vec(reader, shape.m - shape.k_skip)?,
        final_a_eval: reader.f256()?,
        final_b_eval: reader.f256()?,
        final_c_eval: reader.f256()?,
    };
    let lincheck = noid_ivc_core::lincheck::c1::C1LincheckProof {
        rounds: decode_f256_pair_vec(reader, shape.k_log - shape.k_skip)?,
        z_partial: decode_f256_vec(reader, skip)?,
    };
    let pcs_open = decode_basefold(reader, &BaseFoldWireShape::derive(params)?)?;
    Ok(C1FieldR1csProof {
        zerocheck,
        lincheck,
        pcs_open,
    })
}

fn encode_query(
    out: &mut Vec<u8>,
    query: &C1QueryOpening,
    shape: &BaseFoldWireShape,
) -> Result<(), HistoryStepError> {
    let position = u64::try_from(query.position).map_err(|_| HistoryStepError::WireEncoding)?;
    out.extend_from_slice(&position.to_le_bytes());
    encode_f128_vec(out, &query.initial_leaf, shape.initial_leaf)?;
    encode_hash_vec(out, &query.initial_path, shape.initial_path)?;
    encode_f256_vec(out, &query.post_row_batch_leaf, shape.post_row_batch_leaf)?;
    encode_hash_vec(out, &query.post_row_batch_path, shape.post_row_batch_path)?;
    if query.epoch_leaves.len() != shape.epoch_shapes.len()
        || query.epoch_paths.len() != shape.epoch_shapes.len()
    {
        return Err(HistoryStepError::WireEncoding);
    }
    for (index, (leaf, path)) in shape.epoch_shapes.iter().enumerate() {
        encode_f256_vec(out, &query.epoch_leaves[index], *leaf)?;
        encode_hash_vec(out, &query.epoch_paths[index], *path)?;
    }
    Ok(())
}

fn decode_query(
    reader: &mut Reader<'_>,
    shape: &BaseFoldWireShape,
) -> Result<C1QueryOpening, HistoryStepError> {
    let position = usize::try_from(reader.u64()?).map_err(|_| HistoryStepError::WireEncoding)?;
    let initial_leaf = decode_f128_vec(reader, shape.initial_leaf)?;
    let initial_path = decode_hash_vec(reader, shape.initial_path)?;
    let post_row_batch_leaf = decode_f256_vec(reader, shape.post_row_batch_leaf)?;
    let post_row_batch_path = decode_hash_vec(reader, shape.post_row_batch_path)?;
    let mut epoch_leaves = Vec::with_capacity(shape.epoch_shapes.len());
    let mut epoch_paths = Vec::with_capacity(shape.epoch_shapes.len());
    for (leaf, path) in &shape.epoch_shapes {
        epoch_leaves.push(decode_f256_vec(reader, *leaf)?);
        epoch_paths.push(decode_hash_vec(reader, *path)?);
    }
    Ok(C1QueryOpening {
        position,
        initial_leaf,
        initial_path,
        post_row_batch_leaf,
        post_row_batch_path,
        epoch_leaves,
        epoch_paths,
    })
}

fn encode_basefold(
    out: &mut Vec<u8>,
    proof: &C1BaseFoldProof,
    shape: &BaseFoldWireShape,
) -> Result<(), HistoryStepError> {
    if proof.round_messages.len() != shape.round_messages
        || proof.round_commitments.len() != shape.round_commitments
        || proof.queries.len() != shape.queries
    {
        return Err(HistoryStepError::WireEncoding);
    }
    for message in &proof.round_messages {
        put_f256(out, message.u_0);
        put_f256(out, message.u_2);
    }
    put_hash(out, &proof.post_row_batch_commit.root);
    for commitment in &proof.round_commitments {
        put_hash(out, &commitment.root);
    }
    put_f256(out, proof.final_a);
    put_f256(out, proof.final_b);
    encode_f256_vec(out, &proof.final_codeword, shape.final_codeword)?;
    encode_f256_vec(out, &proof.plaintext_tail, shape.plaintext_tail)?;
    out.extend_from_slice(&proof.pow_nonce.to_le_bytes());
    for query in &proof.queries {
        encode_query(out, query, shape)?;
    }
    Ok(())
}

fn decode_basefold(
    reader: &mut Reader<'_>,
    shape: &BaseFoldWireShape,
) -> Result<C1BaseFoldProof, HistoryStepError> {
    let mut round_messages = Vec::with_capacity(shape.round_messages);
    for _ in 0..shape.round_messages {
        round_messages.push(C1RoundMessage {
            u_0: reader.f256()?,
            u_2: reader.f256()?,
        });
    }
    let post_row_batch_commit = RoundCommitment {
        root: reader.hash()?,
    };
    let mut round_commitments = Vec::with_capacity(shape.round_commitments);
    for _ in 0..shape.round_commitments {
        round_commitments.push(RoundCommitment {
            root: reader.hash()?,
        });
    }
    let final_a = reader.f256()?;
    let final_b = reader.f256()?;
    let final_codeword = decode_f256_vec(reader, shape.final_codeword)?;
    let plaintext_tail = decode_f256_vec(reader, shape.plaintext_tail)?;
    let pow_nonce = reader.u64()?;
    let mut queries = Vec::with_capacity(shape.queries);
    for _ in 0..shape.queries {
        queries.push(decode_query(reader, shape)?);
    }
    Ok(C1BaseFoldProof {
        round_messages,
        post_row_batch_commit,
        round_commitments,
        final_a,
        final_b,
        final_codeword,
        plaintext_tail,
        pow_nonce,
        queries,
    })
}

pub fn encode_history_step_terminal(
    runtime: &HistoryStepRuntime,
    terminal: &HistoryStepTerminal,
) -> Result<Vec<u8>, HistoryStepError> {
    validate_terminal_metadata(runtime, terminal, None)?;
    let entry = runtime.bank().entry(terminal.class_id);
    let expected = terminal_len_for_class(runtime, terminal.class_id)?;
    let block_vk = runtime
        .direct_block_vk(terminal.class_id.current_slot())
        .ok_or(HistoryStepError::RuntimeBlockVk(
            terminal.class_id.current_slot(),
        ))?;
    let sidecar = encode_joint_c1_region_sidecar_canonical(
        runtime.parent_recursion_vk(),
        block_vk,
        entry.shape().m,
        &terminal.proof.sidecar,
    )?;
    let mut out = Vec::with_capacity(expected);
    out.push(HISTORY_STEP_WIRE_VERSION);
    out.extend_from_slice(&terminal.height.to_le_bytes());
    out.extend_from_slice(&terminal.semantic_id);
    out.push(terminal.class_id.wire_id());
    put_hash(&mut out, &terminal.proof.commitment.root);
    encode_f128_vec(&mut out, &terminal.proof.io, runtime.bank().spec().io_len)?;
    encode_field_proof(
        &mut out,
        &terminal.proof.field_proof,
        entry.shape(),
        entry.pcs_params(),
    )?;
    out.extend_from_slice(&sidecar);
    if out.len() != expected {
        return Err(HistoryStepError::WireLength {
            expected,
            actual: out.len(),
        });
    }
    Ok(out)
}

pub fn decode_history_step_terminal(
    runtime: &HistoryStepRuntime,
    bytes: &[u8],
) -> Result<HistoryStepTerminal, HistoryStepError> {
    if bytes.len() < PREFIX_BYTES {
        return Err(HistoryStepError::WireLength {
            expected: PREFIX_BYTES,
            actual: bytes.len(),
        });
    }
    let mut prefix = Reader::new(&bytes[..PREFIX_BYTES]);
    if prefix.u8()? != HISTORY_STEP_WIRE_VERSION {
        return Err(HistoryStepError::WireVersion);
    }
    let height = prefix.u64()?;
    let semantic_id = prefix.hash()?;
    let class_id = CanonicalHistoryStepClassId::from_index(prefix.u8()? as usize)
        .ok_or(HistoryStepError::InvalidClass)?;
    prefix.finish()?;
    let expected = terminal_len_for_class(runtime, class_id)?;
    if bytes.len() != expected {
        return Err(HistoryStepError::WireLength {
            expected,
            actual: bytes.len(),
        });
    }

    // All following allocations have class-derived exact dimensions, and
    // are reached only after the complete wire length matches those bounds.
    let entry = runtime.bank().entry(class_id);
    let mut reader = Reader::new(&bytes[PREFIX_BYTES..]);
    let commitment_root = reader.hash()?;
    let io = decode_f128_vec(&mut reader, runtime.bank().spec().io_len)?;
    let field_proof = decode_field_proof(&mut reader, entry.shape(), entry.pcs_params())?;
    let block_vk = runtime
        .direct_block_vk(class_id.current_slot())
        .ok_or(HistoryStepError::RuntimeBlockVk(class_id.current_slot()))?;
    let sidecar_len = canonical_joint_c1_region_sidecar_len(
        runtime.parent_recursion_vk(),
        block_vk,
        entry.shape().m,
    )?;
    let sidecar = decode_joint_c1_region_sidecar_canonical(
        runtime.parent_recursion_vk(),
        block_vk,
        entry.shape().m,
        reader.take(sidecar_len)?,
    )?;
    reader.finish()?;
    let proof = HistoryStepProof {
        field_proof,
        commitment: Commitment {
            root: commitment_root,
            params: entry.pcs_params().clone(),
        },
        io,
        sidecar,
    };
    let accumulator = history_step_bank_block_accumulator(runtime.bank(), &proof.io)?;
    let terminal = HistoryStepTerminal {
        height,
        semantic_id,
        class_id,
        accumulator,
        proof,
    };
    validate_terminal_metadata(runtime, &terminal, None)?;
    Ok(terminal)
}

pub fn decode_verify_history_step_terminal(
    runtime: &HistoryStepRuntime,
    bytes: &[u8],
    expected_header: &BlockHeader,
    epoch_anchor_header: &BlockHeader,
) -> Result<AcceptedHistoryStepTerminal, HistoryStepError> {
    let terminal = decode_history_step_terminal(runtime, bytes)?;
    verify_history_step_terminal(runtime, &terminal, expected_header, epoch_anchor_header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::history_step_bank::{
        canonical_history_step_pcs_params, HISTORY_STEP_FRI_QUERIES,
    };

    #[test]
    fn c1_history_basefold_wire_shapes_are_exact() {
        let expected = [
            // B64: k_code=20, FRI arities [4,4,4,4,2].
            (0usize, 20usize, 3_848usize, 521_744usize),
            // B255: k_code=21, FRI arities [4,4,4,4,3].
            (1usize, 21usize, 3_976usize, 547_024usize),
        ];

        for (class_index, expected_k_code, expected_query_bytes, expected_total) in expected {
            let class = CanonicalHistoryStepClassId::from_index(class_index)
                .expect("canonical History class");
            let params = canonical_history_step_pcs_params(class);
            let shape = BaseFoldWireShape::derive(&params).expect("canonical BaseFold wire shape");
            assert_eq!(params.k_code(), expected_k_code);
            assert_eq!(shape.queries, HISTORY_STEP_FRI_QUERIES);
            assert_eq!(
                shape
                    .query_encoded_len()
                    .expect("canonical query wire length"),
                expected_query_bytes
            );
            assert_eq!(
                shape.encoded_len().expect("canonical BaseFold wire length"),
                expected_total
            );
        }
    }
}
