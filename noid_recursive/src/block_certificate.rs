// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Data-only accepted-block certificate statement for recursive history proofs.
//!
//! This module is intentionally independent of `noid_block`: the final
//! recursive verifier lives here and must not depend on block-validation code.
//! `noid_block` builds these statements after full `AcceptBlock` validation.

use crate::checkpoint_proof::HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    discharge_fixed_field_hash_reductions_native, prove_fixed_field_hash_killshot,
    verify_fixed_field_hash_killshot, FixedFieldHashInputs, FixedFieldHashParams,
    FixedFieldHashProofKillShot,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::{
    capacity_iv, poseidon2b_hash_byte_slices, Poseidon2bSponge, TAG_HISTPRF,
};
use noid_poseidon2b::primitives::Digest;

pub const ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION: u32 = 1;
pub const ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS: usize = 35;
pub const ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS: usize =
    ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS + 3;
pub const ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS: usize = 40;
pub const ACCEPTED_BLOCK_CERTIFICATE_PROOF_VERSION: u32 = 1;

const ABC_STMT1: u128 = 0x4142_435F_5354_4D31; // "ABC_STM1"
const ABC_BATCH1: u128 = 0x4142_435F_4241_5431; // "ABC_BAT1"
const ABC_BODY1: &[u8] = b"NOID:ABC:BLOCK_BODY:V1";
const ABC_PROOF1: &[u8] = b"NOID:ABC:BLOCK_PROOF:V1";
const ABC_AUTH1: &[u8] = b"NOID:ABC:AUTH_SIDECAR:V1";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateStatementV1 {
    pub version: u32,
    pub accept_block_predicate_version: u32,
    pub height: u64,
    pub block_id: Digest,
    pub parent_block_id: Digest,
    pub parent_state_root: Digest,
    pub child_state_root: Digest,
    pub tx_root: Digest,
    pub block_body_digest: Digest,
    pub block_proof_digest: Digest,
    pub auth_sidecar_digest: Digest,
    pub accepted_block_claim_digest: Digest,
    pub accepted_state_transition_claim_digest: Digest,
    pub exact_transition_digest: Digest,
    pub tx_count: u32,
    pub user_tx_count: u32,
    pub live_input_count: u32,
    pub live_output_count: u32,
    pub state_frontier_node_count: u32,
    pub touched_slot_count: u32,
    pub action_count: u32,
    pub block_body_len: u64,
    pub block_proof_len: u64,
    pub auth_sidecar_len: u64,
}

impl AcceptedBlockCertificateStatementV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateStatementV1 length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateProofV1 {
    pub version: u32,
    pub statement_digest: Digest,
    pub backend_proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateBackendProofV1 {
    pub version: u32,
    pub statement_digest_hash: FixedFieldHashProofKillShot,
}

impl AcceptedBlockCertificateBackendProofV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateBackendProofV1 length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateBatchDigestProofV1 {
    pub version: u32,
    pub batch_statement_digest_hash: FixedFieldHashProofKillShot,
}

impl AcceptedBlockCertificateBatchDigestProofV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateBatchDigestProofV1 length fits usize")
            as usize
    }
}

impl AcceptedBlockCertificateProofV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateProofV1 length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateBatchStatementV1 {
    pub version: u32,
    pub batch_len: u32,
    pub accepted_claim_batch_digest: Digest,
    pub certificate_statement_digests: [Digest; HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize],
}

impl AcceptedBlockCertificateBatchStatementV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateBatchStatementV1 length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockCertificateProofError {
    UnsupportedVersion { actual: u32 },
    StatementDigestMismatch,
    EmptyBackendProof,
    DecodeBackendProof,
    BadStatementDigestProof,
    BadStatementDigestDischarge,
    BadBatchStatementDigestProof,
    BadBatchStatementDigestDischarge,
    BackendVerifierMissing,
}

impl std::fmt::Display for AcceptedBlockCertificateProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { actual } => {
                write!(
                    f,
                    "unsupported accepted-block certificate proof version {actual}"
                )
            }
            Self::StatementDigestMismatch => {
                write!(f, "accepted-block certificate statement digest mismatch")
            }
            Self::EmptyBackendProof => write!(f, "empty accepted-block certificate backend proof"),
            Self::DecodeBackendProof => write!(f, "bad accepted-block certificate backend proof"),
            Self::BadStatementDigestProof => {
                write!(f, "bad accepted-block certificate statement digest proof")
            }
            Self::BadStatementDigestDischarge => write!(
                f,
                "accepted-block certificate statement digest proof failed native discharge"
            ),
            Self::BadBatchStatementDigestProof => {
                write!(
                    f,
                    "bad accepted-block certificate batch statement digest proof"
                )
            }
            Self::BadBatchStatementDigestDischarge => write!(
                f,
                "accepted-block certificate batch statement digest proof failed native discharge"
            ),
            Self::BackendVerifierMissing => {
                write!(
                    f,
                    "accepted-block certificate recursive verifier is not implemented"
                )
            }
        }
    }
}

impl std::error::Error for AcceptedBlockCertificateProofError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockCertificateBatchError {
    EmptyBatch,
    TooManyStatements { actual: usize },
    ClaimCountMismatch { statements: usize, claims: usize },
    ClaimProjectionMismatch { index: usize },
}

impl std::fmt::Display for AcceptedBlockCertificateBatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBatch => write!(f, "empty accepted-block certificate batch"),
            Self::TooManyStatements { actual } => {
                write!(f, "too many accepted-block certificate statements: {actual}")
            }
            Self::ClaimCountMismatch { statements, claims } => write!(
                f,
                "accepted-block certificate statement/claim count mismatch: {statements} statements, {claims} claims"
            ),
            Self::ClaimProjectionMismatch { index } => {
                write!(f, "accepted-block certificate claim projection mismatch at {index}")
            }
        }
    }
}

impl std::error::Error for AcceptedBlockCertificateBatchError {}

pub fn accepted_block_certificate_statement_fields_v1(
    statement: &AcceptedBlockCertificateStatementV1,
) -> [Block128; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS] {
    let mut fields = [Block128::ZERO; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS];
    let mut index = 0usize;
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.version as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.accept_block_predicate_version as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.height as u128),
    );
    push_digest_fields(&mut fields, &mut index, &statement.block_id);
    push_digest_fields(&mut fields, &mut index, &statement.parent_block_id);
    push_digest_fields(&mut fields, &mut index, &statement.parent_state_root);
    push_digest_fields(&mut fields, &mut index, &statement.child_state_root);
    push_digest_fields(&mut fields, &mut index, &statement.tx_root);
    push_digest_fields(&mut fields, &mut index, &statement.block_body_digest);
    push_digest_fields(&mut fields, &mut index, &statement.block_proof_digest);
    push_digest_fields(&mut fields, &mut index, &statement.auth_sidecar_digest);
    push_digest_fields(
        &mut fields,
        &mut index,
        &statement.accepted_block_claim_digest,
    );
    push_digest_fields(
        &mut fields,
        &mut index,
        &statement.accepted_state_transition_claim_digest,
    );
    push_digest_fields(&mut fields, &mut index, &statement.exact_transition_digest);
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.tx_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.user_tx_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.live_input_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.live_output_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.state_frontier_node_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.touched_slot_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.action_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.block_body_len as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.block_proof_len as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.auth_sidecar_len as u128),
    );
    debug_assert_eq!(index, ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS);
    fields
}

pub fn accepted_block_certificate_statement_digest_v1(
    statement: &AcceptedBlockCertificateStatementV1,
) -> Digest {
    digest_fixed_no_pad_from_fields(&accepted_block_certificate_statement_hash_fields_v1(
        statement,
    ))
}

pub fn accepted_block_certificate_statement_hash_fields_v1(
    statement: &AcceptedBlockCertificateStatementV1,
) -> [Block128; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS] {
    let statement_fields = accepted_block_certificate_statement_fields_v1(statement);
    let mut fields = [Block128::ZERO; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS];
    fields[0] = Block128::from(ABC_STMT1);
    fields[1] = Block128::from((ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS + 1) as u128);
    fields[2..2 + ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS].copy_from_slice(&statement_fields);
    fields
}

pub fn accepted_block_certificate_statement_hash_params_v1() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS,
    )
    .expect("accepted-block certificate statement hash schedule is valid")
}

pub fn accepted_block_certificate_chain_claim_v1(
    statement: &AcceptedBlockCertificateStatementV1,
) -> [Block128; 2] {
    digest_to_fields(&statement.accepted_block_claim_digest)
}

pub fn accepted_block_certificate_block_body_digest_v1(bytes: &[u8]) -> Digest {
    certificate_bytes_digest(ABC_BODY1, bytes)
}

pub fn accepted_block_certificate_block_proof_digest_v1(bytes: &[u8]) -> Digest {
    certificate_bytes_digest(ABC_PROOF1, bytes)
}

pub fn accepted_block_certificate_auth_sidecar_digest_v1(bytes: &[u8]) -> Digest {
    certificate_bytes_digest(ABC_AUTH1, bytes)
}

pub fn accepted_block_certificate_batch_statement_v1(
    statements: &[AcceptedBlockCertificateStatementV1],
    accepted_block_claims: &[[Block128; 2]],
    accepted_claim_batch_digest: Digest,
) -> Result<AcceptedBlockCertificateBatchStatementV1, AcceptedBlockCertificateBatchError> {
    if statements.is_empty() {
        return Err(AcceptedBlockCertificateBatchError::EmptyBatch);
    }
    if statements.len() > HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize {
        return Err(AcceptedBlockCertificateBatchError::TooManyStatements {
            actual: statements.len(),
        });
    }
    if statements.len() != accepted_block_claims.len() {
        return Err(AcceptedBlockCertificateBatchError::ClaimCountMismatch {
            statements: statements.len(),
            claims: accepted_block_claims.len(),
        });
    }

    let mut certificate_statement_digests =
        [[0u8; 32]; HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize];
    for (index, (statement, claim)) in statements
        .iter()
        .zip(accepted_block_claims.iter().copied())
        .enumerate()
    {
        if accepted_block_certificate_chain_claim_v1(statement) != claim {
            return Err(AcceptedBlockCertificateBatchError::ClaimProjectionMismatch { index });
        }
        certificate_statement_digests[index] =
            accepted_block_certificate_statement_digest_v1(statement);
    }

    Ok(AcceptedBlockCertificateBatchStatementV1 {
        version: ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
        batch_len: statements
            .len()
            .try_into()
            .expect("checkpoint batch target fits u32"),
        accepted_claim_batch_digest,
        certificate_statement_digests,
    })
}

pub fn accepted_block_certificate_batch_statement_digest_v1(
    statement: &AcceptedBlockCertificateBatchStatementV1,
) -> Digest {
    digest_fixed_no_pad_from_fields(&accepted_block_certificate_batch_statement_hash_fields_v1(
        statement,
    ))
}

pub fn accepted_block_certificate_batch_statement_hash_fields_v1(
    statement: &AcceptedBlockCertificateBatchStatementV1,
) -> [Block128; ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS];
    let mut index = 0usize;
    fields[index] = Block128::from(ABC_BATCH1);
    index += 1;
    fields[index] = Block128::from(38u128);
    index += 1;
    fields[index] = Block128::from(statement.version as u128);
    index += 1;
    fields[index] = Block128::from(statement.batch_len as u128);
    index += 1;
    fields[index] = Block128::from(HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as u128);
    index += 1;
    push_digest_hash_fields(
        &mut fields,
        &mut index,
        &statement.accepted_claim_batch_digest,
    );
    for digest in &statement.certificate_statement_digests {
        push_digest_hash_fields(&mut fields, &mut index, digest);
    }
    debug_assert_eq!(
        index + 1,
        ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS
    );
    fields
}

pub fn accepted_block_certificate_batch_statement_hash_params_v1() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS,
    )
    .expect("accepted-block certificate batch statement hash schedule is valid")
}

pub fn prove_accepted_block_certificate_digest_backend_v1(
    statement: &AcceptedBlockCertificateStatementV1,
) -> Result<AcceptedBlockCertificateBackendProofV1, AcceptedBlockCertificateProofError> {
    let fields = accepted_block_certificate_statement_hash_fields_v1(statement);
    let expected_digest = accepted_block_certificate_statement_digest_v1(statement);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = accepted_block_certificate_statement_hash_params_v1();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let (statement_digest_hash, reductions) =
        prove_fixed_field_hash_killshot(params, &inputs, &mut channel);
    if !discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        return Err(AcceptedBlockCertificateProofError::BadStatementDigestDischarge);
    }
    Ok(AcceptedBlockCertificateBackendProofV1 {
        version: ACCEPTED_BLOCK_CERTIFICATE_PROOF_VERSION,
        statement_digest_hash,
    })
}

pub fn verify_accepted_block_certificate_digest_backend_v1(
    statement: &AcceptedBlockCertificateStatementV1,
    proof: &AcceptedBlockCertificateBackendProofV1,
) -> Result<(), AcceptedBlockCertificateProofError> {
    if proof.version != ACCEPTED_BLOCK_CERTIFICATE_PROOF_VERSION {
        return Err(AcceptedBlockCertificateProofError::UnsupportedVersion {
            actual: proof.version,
        });
    }
    let fields = accepted_block_certificate_statement_hash_fields_v1(statement);
    let expected_digest = accepted_block_certificate_statement_digest_v1(statement);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = accepted_block_certificate_statement_hash_params_v1();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let reductions = verify_fixed_field_hash_killshot(
        params,
        &proof.statement_digest_hash,
        &inputs,
        &mut channel,
    )
    .ok_or(AcceptedBlockCertificateProofError::BadStatementDigestProof)?;
    if discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        Ok(())
    } else {
        Err(AcceptedBlockCertificateProofError::BadStatementDigestDischarge)
    }
}

pub fn prove_accepted_block_certificate_proof_v1_hash_only(
    statement: &AcceptedBlockCertificateStatementV1,
) -> Result<AcceptedBlockCertificateProofV1, AcceptedBlockCertificateProofError> {
    let backend = prove_accepted_block_certificate_digest_backend_v1(statement)?;
    Ok(AcceptedBlockCertificateProofV1 {
        version: ACCEPTED_BLOCK_CERTIFICATE_PROOF_VERSION,
        statement_digest: accepted_block_certificate_statement_digest_v1(statement),
        backend_proof: bincode::serialize(&backend)
            .expect("AcceptedBlockCertificateBackendProofV1 serializes"),
    })
}

pub fn prove_accepted_block_certificate_batch_digest_proof_v1(
    statement: &AcceptedBlockCertificateBatchStatementV1,
) -> Result<AcceptedBlockCertificateBatchDigestProofV1, AcceptedBlockCertificateProofError> {
    let fields = accepted_block_certificate_batch_statement_hash_fields_v1(statement);
    let expected_digest = accepted_block_certificate_batch_statement_digest_v1(statement);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = accepted_block_certificate_batch_statement_hash_params_v1();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let (batch_statement_digest_hash, reductions) =
        prove_fixed_field_hash_killshot(params, &inputs, &mut channel);
    if !discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        return Err(AcceptedBlockCertificateProofError::BadBatchStatementDigestDischarge);
    }
    Ok(AcceptedBlockCertificateBatchDigestProofV1 {
        version: ACCEPTED_BLOCK_CERTIFICATE_PROOF_VERSION,
        batch_statement_digest_hash,
    })
}

pub fn verify_accepted_block_certificate_batch_digest_proof_v1(
    statement: &AcceptedBlockCertificateBatchStatementV1,
    proof: &AcceptedBlockCertificateBatchDigestProofV1,
) -> Result<(), AcceptedBlockCertificateProofError> {
    if proof.version != ACCEPTED_BLOCK_CERTIFICATE_PROOF_VERSION {
        return Err(AcceptedBlockCertificateProofError::UnsupportedVersion {
            actual: proof.version,
        });
    }
    let fields = accepted_block_certificate_batch_statement_hash_fields_v1(statement);
    let expected_digest = accepted_block_certificate_batch_statement_digest_v1(statement);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = accepted_block_certificate_batch_statement_hash_params_v1();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let reductions = verify_fixed_field_hash_killshot(
        params,
        &proof.batch_statement_digest_hash,
        &inputs,
        &mut channel,
    )
    .ok_or(AcceptedBlockCertificateProofError::BadBatchStatementDigestProof)?;
    if discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        Ok(())
    } else {
        Err(AcceptedBlockCertificateProofError::BadBatchStatementDigestDischarge)
    }
}

pub fn verify_accepted_block_certificate_proof_v1_untrusted(
    statement: &AcceptedBlockCertificateStatementV1,
    proof: &AcceptedBlockCertificateProofV1,
) -> Result<(), AcceptedBlockCertificateProofError> {
    if proof.version != ACCEPTED_BLOCK_CERTIFICATE_PROOF_VERSION {
        return Err(AcceptedBlockCertificateProofError::UnsupportedVersion {
            actual: proof.version,
        });
    }
    let expected_digest = accepted_block_certificate_statement_digest_v1(statement);
    if proof.statement_digest != expected_digest {
        return Err(AcceptedBlockCertificateProofError::StatementDigestMismatch);
    }
    if proof.backend_proof.is_empty() {
        return Err(AcceptedBlockCertificateProofError::EmptyBackendProof);
    }
    let backend: AcceptedBlockCertificateBackendProofV1 =
        bincode::deserialize(&proof.backend_proof)
            .map_err(|_| AcceptedBlockCertificateProofError::DecodeBackendProof)?;
    verify_accepted_block_certificate_digest_backend_v1(statement, &backend)?;

    Err(AcceptedBlockCertificateProofError::BackendVerifierMissing)
}

fn certificate_bytes_digest(domain: &[u8], bytes: &[u8]) -> Digest {
    poseidon2b_hash_byte_slices(domain, &[bytes])
}

fn push_field(
    fields: &mut [Block128; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS],
    index: &mut usize,
    value: Block128,
) {
    debug_assert!(*index < ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS);
    fields[*index] = value;
    *index += 1;
}

fn push_digest_fields(
    fields: &mut [Block128; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS],
    index: &mut usize,
    digest: &Digest,
) {
    let [lo, hi] = digest_to_fields(digest);
    push_field(fields, index, lo);
    push_field(fields, index, hi);
}

fn push_digest_hash_fields<const N: usize>(
    fields: &mut [Block128; N],
    index: &mut usize,
    digest: &Digest,
) {
    let [lo, hi] = digest_to_fields(digest);
    fields[*index] = lo;
    *index += 1;
    fields[*index] = hi;
    *index += 1;
}

fn digest_to_fields(digest: &Digest) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

fn digest_fixed_no_pad_from_fields(fields: &[Block128]) -> Digest {
    debug_assert_eq!(fields.len() % 2, 0);
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    for pair in fields.chunks_exact(2) {
        sponge.absorb_pair(pair[0], pair[1]);
    }
    sponge.finalize_no_pad()
}

fn fixed_hash_input(fields: &[Block128], expected_digest: &Digest) -> FixedFieldHashInputs {
    FixedFieldHashInputs {
        fields: fields.to_vec(),
        expected_digest: digest_to_fields(expected_digest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> AcceptedBlockCertificateStatementV1 {
        AcceptedBlockCertificateStatementV1 {
            version: ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
            accept_block_predicate_version: 1,
            height: 7,
            block_id: [0x01; 32],
            parent_block_id: [0x02; 32],
            parent_state_root: [0x03; 32],
            child_state_root: [0x04; 32],
            tx_root: [0x05; 32],
            block_body_digest: accepted_block_certificate_block_body_digest_v1(b"body"),
            block_proof_digest: accepted_block_certificate_block_proof_digest_v1(b"proof"),
            auth_sidecar_digest: accepted_block_certificate_auth_sidecar_digest_v1(b"auth"),
            accepted_block_claim_digest: [0x06; 32],
            accepted_state_transition_claim_digest: [0x07; 32],
            exact_transition_digest: [0x08; 32],
            tx_count: 2,
            user_tx_count: 1,
            live_input_count: 3,
            live_output_count: 4,
            state_frontier_node_count: 5,
            touched_slot_count: 6,
            action_count: 7,
            block_body_len: 8,
            block_proof_len: 9,
            auth_sidecar_len: 10,
        }
    }

    #[test]
    fn accepted_block_certificate_statement_has_fixed_fields_and_digest() {
        let stmt = statement();
        assert_eq!(
            accepted_block_certificate_statement_fields_v1(&stmt).len(),
            ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS
        );
        assert_eq!(
            accepted_block_certificate_statement_hash_fields_v1(&stmt).len(),
            ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS
        );
        assert_ne!(
            accepted_block_certificate_statement_digest_v1(&stmt),
            [0u8; 32]
        );

        let mut tampered = stmt.clone();
        tampered.child_state_root = [0xAA; 32];
        assert_ne!(
            accepted_block_certificate_statement_digest_v1(&stmt),
            accepted_block_certificate_statement_digest_v1(&tampered)
        );
    }

    #[test]
    fn accepted_block_certificate_chain_claim_projects_folded_claim_digest() {
        let stmt = statement();
        let projected = accepted_block_certificate_chain_claim_v1(&stmt);
        let expected = digest_to_fields(&stmt.accepted_block_claim_digest);
        assert_eq!(projected, expected);
    }

    #[test]
    fn accepted_block_certificate_byte_domains_are_separated() {
        let body = accepted_block_certificate_block_body_digest_v1(b"same");
        let proof = accepted_block_certificate_block_proof_digest_v1(b"same");
        let auth = accepted_block_certificate_auth_sidecar_digest_v1(b"same");
        assert_ne!(body, proof);
        assert_ne!(body, auth);
        assert_ne!(proof, auth);
    }

    #[test]
    fn accepted_block_certificate_recursive_proof_skeleton_fails_closed() {
        let stmt = statement();
        let good_shape =
            prove_accepted_block_certificate_proof_v1_hash_only(&stmt).expect("hash proof builds");
        let backend: AcceptedBlockCertificateBackendProofV1 =
            bincode::deserialize(&good_shape.backend_proof).expect("backend proof decodes");
        verify_accepted_block_certificate_digest_backend_v1(&stmt, &backend)
            .expect("statement digest backend verifies");
        assert_eq!(
            verify_accepted_block_certificate_proof_v1_untrusted(&stmt, &good_shape),
            Err(AcceptedBlockCertificateProofError::BackendVerifierMissing)
        );

        let mut bad = good_shape.clone();
        bad.version += 1;
        assert!(matches!(
            verify_accepted_block_certificate_proof_v1_untrusted(&stmt, &bad),
            Err(AcceptedBlockCertificateProofError::UnsupportedVersion { .. })
        ));

        let mut bad = good_shape.clone();
        bad.statement_digest = [0x99; 32];
        assert_eq!(
            verify_accepted_block_certificate_proof_v1_untrusted(&stmt, &bad),
            Err(AcceptedBlockCertificateProofError::StatementDigestMismatch)
        );

        let mut bad = good_shape.clone();
        bad.backend_proof.clear();
        assert_eq!(
            verify_accepted_block_certificate_proof_v1_untrusted(&stmt, &bad),
            Err(AcceptedBlockCertificateProofError::EmptyBackendProof)
        );

        let mut bad = good_shape;
        bad.backend_proof = vec![0x42];
        assert_eq!(
            verify_accepted_block_certificate_proof_v1_untrusted(&stmt, &bad),
            Err(AcceptedBlockCertificateProofError::DecodeBackendProof)
        );
    }

    #[test]
    fn accepted_block_certificate_statement_digest_backend_rejects_tamper() {
        let stmt = statement();
        let backend = prove_accepted_block_certificate_digest_backend_v1(&stmt)
            .expect("statement digest proof builds");
        let mut tampered = stmt;
        tampered.accepted_block_claim_digest = [0xAB; 32];
        assert_eq!(
            verify_accepted_block_certificate_digest_backend_v1(&tampered, &backend),
            Err(AcceptedBlockCertificateProofError::BadStatementDigestProof)
        );
    }

    #[test]
    fn accepted_block_certificate_batch_statement_binds_claim_projection_and_padding() {
        let stmt = statement();
        let claim = accepted_block_certificate_chain_claim_v1(&stmt);
        let batch =
            accepted_block_certificate_batch_statement_v1(&[stmt.clone()], &[claim], [0x55; 32])
                .expect("batch statement builds");
        assert_eq!(
            accepted_block_certificate_batch_statement_hash_fields_v1(&batch).len(),
            ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS
        );
        assert_eq!(batch.batch_len, 1);
        assert_eq!(
            batch.certificate_statement_digests[0],
            accepted_block_certificate_statement_digest_v1(&stmt)
        );
        assert_eq!(batch.certificate_statement_digests[1], [0u8; 32]);
        assert_ne!(
            accepted_block_certificate_batch_statement_digest_v1(&batch),
            [0u8; 32]
        );
        let batch_digest_proof = prove_accepted_block_certificate_batch_digest_proof_v1(&batch)
            .expect("batch digest proof builds");
        verify_accepted_block_certificate_batch_digest_proof_v1(&batch, &batch_digest_proof)
            .expect("batch digest proof verifies");

        let mut tampered_batch = batch.clone();
        tampered_batch.certificate_statement_digests[0] = [0x99; 32];
        assert_eq!(
            verify_accepted_block_certificate_batch_digest_proof_v1(
                &tampered_batch,
                &batch_digest_proof
            ),
            Err(AcceptedBlockCertificateProofError::BadBatchStatementDigestProof)
        );

        let bad_claim = [Block128::ONE, claim[1]];
        assert_eq!(
            accepted_block_certificate_batch_statement_v1(&[stmt], &[bad_claim], [0x55; 32]),
            Err(AcceptedBlockCertificateBatchError::ClaimProjectionMismatch { index: 0 })
        );
    }
}
