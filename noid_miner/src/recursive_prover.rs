// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production coordinator for one selected-ZK recursive Block proof.
//!
//! Native block acceptance remains the cheap `BlockProof::minimal` path. This
//! module is for the asynchronous history prover: it consumes the exact
//! selected authorization proofs retained from one native-verified block,
//! chooses the canonical B8/B32/B64/B255 class, creates one fresh verified
//! ghost proof, and authors only the selected V4 recursive envelope.

use std::panic::{catch_unwind, AssertUnwindSafe};

use noid_core::TowerField;
use noid_gkr::zk_authorization::{
    verify_zk_authorization, ZkAuthCapsuleOwnerStatement, ZkAuthorizationProof,
};
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_recursive::acceptance::block_class::{
    build_selected_zk_block_proof_trace, prove_built_block, BlockClass, BlockProofEnvelope,
    BlockProofError, BLOCK_PROOF_TRANSCRIPT_DOMAIN,
};
use noid_recursive::acceptance::link::{SelectedZkBlockInput, SelectedZkBlockInputError};
use noid_recursive::block_certificate_backend::{
    verify_accepted_block_batch_components_selected_zk, AcceptedBlockBatchComponentError,
    AcceptedBlockBatchComponentInputs, AcceptedBlockBatchComponentProof,
};
use noid_recursive::{ChainAccumulator, RecursiveConsensusState};

use crate::memory_governor::{ProofMemoryGovernor, ProofMemoryPressure};

/// One of the four canonical standalone recursive Block classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedRecursiveTier {
    B8,
    B32,
    B64,
    B255,
}

impl SelectedRecursiveTier {
    pub const fn capacity(self) -> usize {
        match self {
            Self::B8 => 8,
            Self::B32 => 32,
            Self::B64 => 64,
            Self::B255 => 255,
        }
    }
}

/// Borrowed freeze-locked selected class registry used by the history prover.
/// Construction rejects a misplaced tier and every legacy authorization class
/// before any recursive witness allocation begins.
pub struct SelectedRecursiveBlockClasses<'a> {
    b8: &'a BlockClass,
    b32: &'a BlockClass,
    b64: &'a BlockClass,
    b255: &'a BlockClass,
}

impl<'a> SelectedRecursiveBlockClasses<'a> {
    pub fn try_new(
        b8: &'a BlockClass,
        b32: &'a BlockClass,
        b64: &'a BlockClass,
        b255: &'a BlockClass,
    ) -> Result<Self, SelectedRecursiveProverError> {
        for (tier, class) in [(8, b8), (32, b32), (64, b64), (255, b255)] {
            class
                .validate_selected_zk_identity_for_tier(tier)
                .map_err(|source| SelectedRecursiveProverError::ClassIdentity { tier, source })?;
        }
        Ok(Self { b8, b32, b64, b255 })
    }

    fn get(&self, tier: SelectedRecursiveTier) -> &'a BlockClass {
        match tier {
            SelectedRecursiveTier::B8 => self.b8,
            SelectedRecursiveTier::B32 => self.b32,
            SelectedRecursiveTier::B64 => self.b64,
            SelectedRecursiveTier::B255 => self.b255,
        }
    }
}

/// Consuming inputs for exactly one native-verified accepted block.
///
/// The selected proof vector is intentionally owned and the job is neither
/// Clone nor serializable. Callers must transfer it from the bounded native
/// sidecar replay; no legacy proof or padding vector is accepted.
pub struct SelectedRecursiveBlockJob<'a> {
    pub start_consensus: &'a RecursiveConsensusState,
    pub start_accumulator: &'a ChainAccumulator,
    pub end_accumulator: &'a ChainAccumulator,
    pub component_inputs: &'a AcceptedBlockBatchComponentInputs,
    pub component_proof: &'a AcceptedBlockBatchComponentProof,
    pub selected_authorization_proofs: Vec<ZkAuthorizationProof>,
}

/// Complete standalone selected Block envelope plus its canonical class.
pub struct SelectedRecursiveBlockProof {
    pub tier: SelectedRecursiveTier,
    pub envelope: BlockProofEnvelope,
}

#[derive(Debug)]
pub enum SelectedRecursiveProverError {
    NonCanonicalLiveCount {
        actual: usize,
    },
    NotSingleBlock {
        actual: usize,
    },
    ComponentShape(&'static str),
    AuthorizationProofCardinality {
        expected: usize,
        actual: usize,
    },
    LegacyAuthorizationCarrier {
        proofs: usize,
        traces: usize,
    },
    AuthorizationBodyBinding {
        index: usize,
    },
    DuplicateLiveCommitment {
        first: usize,
        second: usize,
    },
    GhostProofGeneration,
    GhostProofRejected,
    LiveGhostCommitmentReuse {
        live_index: usize,
    },
    ComponentProof(AcceptedBlockBatchComponentError),
    Input(SelectedZkBlockInputError),
    ClassIdentity {
        tier: usize,
        source: BlockProofError,
    },
    MemoryPressure {
        required_mib: usize,
        available_mib: usize,
    },
    RecursiveAssemblyRejected,
    BlockProof(BlockProofError),
}

impl core::fmt::Display for SelectedRecursiveProverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonCanonicalLiveCount { actual } => {
                write!(
                    f,
                    "{actual} live user transactions exceed the recursive ladder"
                )
            }
            Self::NotSingleBlock { actual } => {
                write!(f, "selected Block job contains {actual} accepted headers")
            }
            Self::ComponentShape(message) => write!(f, "selected component shape: {message}"),
            Self::AuthorizationProofCardinality { expected, actual } => write!(
                f,
                "selected proof count {actual} does not match live user count {expected}"
            ),
            Self::LegacyAuthorizationCarrier { proofs, traces } => write!(
                f,
                "selected job retains {proofs} legacy proofs and {traces} legacy traces"
            ),
            Self::AuthorizationBodyBinding { index } => {
                write!(f, "authorization {index} does not bind its canonical body")
            }
            Self::DuplicateLiveCommitment { first, second } => write!(
                f,
                "selected authorizations {first} and {second} reuse one source commitment"
            ),
            Self::GhostProofGeneration => write!(f, "fresh selected ghost proof failed"),
            Self::GhostProofRejected => write!(f, "fresh selected ghost proof was rejected"),
            Self::LiveGhostCommitmentReuse { live_index } => write!(
                f,
                "selected authorization {live_index} reuses the ghost source commitment"
            ),
            Self::ComponentProof(source) => {
                write!(f, "retained selected component proof rejected: {source:?}")
            }
            Self::Input(source) => write!(f, "selected recursive input rejected: {source}"),
            Self::ClassIdentity { tier, source } => {
                write!(f, "selected B{tier} class rejected: {source}")
            }
            Self::MemoryPressure {
                required_mib,
                available_mib,
            } => write!(
                f,
                "selected recursive proof needs {required_mib} MiB, {available_mib} MiB available"
            ),
            Self::RecursiveAssemblyRejected => {
                write!(f, "selected recursive assembly failed closed")
            }
            Self::BlockProof(source) => write!(f, "selected Block proof failed: {source}"),
        }
    }
}

impl std::error::Error for SelectedRecursiveProverError {}

impl From<ProofMemoryPressure> for SelectedRecursiveProverError {
    fn from(value: ProofMemoryPressure) -> Self {
        Self::MemoryPressure {
            required_mib: value.required_mib,
            available_mib: value.available_mib,
        }
    }
}

/// Select a canonical proof class from the exact live user-transaction count.
pub fn selected_recursive_tier(
    live_user_txs: usize,
) -> Result<SelectedRecursiveTier, SelectedRecursiveProverError> {
    match noid_chain::consensus::params::user_tx_class_tier(live_user_txs) {
        Some(8) => Ok(SelectedRecursiveTier::B8),
        Some(32) => Ok(SelectedRecursiveTier::B32),
        Some(64) => Ok(SelectedRecursiveTier::B64),
        Some(255) => Ok(SelectedRecursiveTier::B255),
        _ => Err(SelectedRecursiveProverError::NonCanonicalLiveCount {
            actual: live_user_txs,
        }),
    }
}

/// Author one production selected recursive Block proof.
///
/// The process-global governor is acquired before native proof replay, ghost
/// generation, or m22+ assembly. Thus a coinbase-only block still reserves B8
/// and this background job cannot overlap the miner's native proof worker.
pub fn prove_selected_recursive_block(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob<'_>,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    prove_selected_recursive_block_with_governor(classes, job, &ProofMemoryGovernor::global(0))
}

fn prove_selected_recursive_block_with_governor(
    classes: &SelectedRecursiveBlockClasses<'_>,
    job: SelectedRecursiveBlockJob<'_>,
    governor: &ProofMemoryGovernor,
) -> Result<SelectedRecursiveBlockProof, SelectedRecursiveProverError> {
    let live_count = job.component_inputs.authorization_inputs.len();
    let tier = selected_recursive_tier(live_count)?;
    validate_selected_carrier_shape(
        job.component_inputs,
        job.component_proof,
        job.selected_authorization_proofs.len(),
    )?;
    classes
        .get(tier)
        .validate_selected_zk_identity_for_tier(tier.capacity())
        .map_err(|source| SelectedRecursiveProverError::ClassIdentity {
            tier: tier.capacity(),
            source,
        })?;

    let _memory_reservation = governor.try_reserve_for_recursive_tier(tier.capacity())?;

    validate_authorization_body_bindings(
        &job.component_inputs.authorization_inputs,
        &job.component_inputs.tx_body_inputs,
        &job.component_inputs.tx_body_hashes,
    )?;
    // Do not add a third full authorization verification pass here. Native
    // accepted-batch replay already verified these exact proofs, and the
    // consuming selected builder verifies them once more against body-derived
    // aliases before exposing any recursive columns. Shape/body mismatch is
    // rejected above, and a malformed proof makes the caught assembly fail.
    verify_accepted_block_batch_components_selected_zk(
        job.start_consensus,
        job.start_accumulator,
        job.end_accumulator,
        job.component_inputs,
        job.component_proof,
    )
    .map_err(SelectedRecursiveProverError::ComponentProof)?;

    let ghost = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
        .map_err(|_| SelectedRecursiveProverError::GhostProofGeneration)?;
    let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
    let ghost_statement = ZkAuthCapsuleOwnerStatement {
        tx_body_hash: noid_gkr::ghost_tx::ghost_tx_body_hash(),
        address: ghost_body.input_owner.as_fields(),
    };
    verify_zk_authorization(ghost_statement, &ghost)
        .map_err(|_| SelectedRecursiveProverError::GhostProofRejected)?;
    reject_source_commitment_reuse(&job.selected_authorization_proofs, &ghost)?;

    let class = classes.get(tier);
    let build_and_prove = AssertUnwindSafe(|| match tier {
        SelectedRecursiveTier::B8 => build_and_prove_selected::<8>(class, job, ghost),
        SelectedRecursiveTier::B32 => build_and_prove_selected::<32>(class, job, ghost),
        SelectedRecursiveTier::B64 => build_and_prove_selected::<64>(class, job, ghost),
        SelectedRecursiveTier::B255 => build_and_prove_selected::<255>(class, job, ghost),
    });
    let envelope = catch_unwind(build_and_prove)
        .map_err(|_| SelectedRecursiveProverError::RecursiveAssemblyRejected)??;
    Ok(SelectedRecursiveBlockProof { tier, envelope })
}

fn build_and_prove_selected<const TIER: usize>(
    class: &BlockClass,
    job: SelectedRecursiveBlockJob<'_>,
    ghost: ZkAuthorizationProof,
) -> Result<BlockProofEnvelope, SelectedRecursiveProverError> {
    let input = SelectedZkBlockInput::<TIER>::try_new(
        job.start_accumulator,
        job.end_accumulator,
        job.component_inputs,
        job.component_proof,
        job.selected_authorization_proofs,
        ghost,
    )
    .map_err(SelectedRecursiveProverError::Input)?;
    let built = build_selected_zk_block_proof_trace(class, input);
    let mut challenger = FsLaneChallenger::new(BLOCK_PROOF_TRANSCRIPT_DOMAIN);
    prove_built_block(class, &built, &mut challenger)
        .map_err(SelectedRecursiveProverError::BlockProof)
}

fn validate_selected_carrier_shape(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
    selected_proof_count: usize,
) -> Result<(), SelectedRecursiveProverError> {
    validate_selected_carrier_counts(SelectedCarrierCounts {
        block_count: inputs.accepted_claim_witness.headers.len(),
        accepted_claim_count: inputs.accepted_claim_witness.accepted_block_claims.len(),
        accepted_claim_hash_count: inputs.accepted_claim_hash_inputs.len(),
        legacy_proof_count: inputs.authorization_witnesses.len(),
        legacy_trace_count: inputs.authorization_traces.len(),
        authorization_count: inputs.authorization_inputs.len(),
        selected_proof_count,
        authorization_total: inputs.authorization_totals.user_tx_count,
        tx_body_count: inputs.tx_body_inputs.len(),
        tx_body_hash_count: inputs.tx_body_hashes.len(),
        legacy_exact_state_count: inputs.exact_state_killshot_inputs.len(),
        structural_exact_state_count: inputs.exact_state_structural_inputs.len(),
        exact_state_proof_count: proof.exact_state.len(),
    })
}

#[derive(Clone, Copy)]
struct SelectedCarrierCounts {
    block_count: usize,
    accepted_claim_count: usize,
    accepted_claim_hash_count: usize,
    legacy_proof_count: usize,
    legacy_trace_count: usize,
    authorization_count: usize,
    selected_proof_count: usize,
    authorization_total: usize,
    tx_body_count: usize,
    tx_body_hash_count: usize,
    legacy_exact_state_count: usize,
    structural_exact_state_count: usize,
    exact_state_proof_count: usize,
}

fn validate_selected_carrier_counts(
    counts: SelectedCarrierCounts,
) -> Result<(), SelectedRecursiveProverError> {
    if counts.block_count != 1 {
        return Err(SelectedRecursiveProverError::NotSingleBlock {
            actual: counts.block_count,
        });
    }
    if counts.accepted_claim_count != 1
        || counts.accepted_claim_hash_count != 1
        || counts.legacy_exact_state_count != 1
        || counts.structural_exact_state_count != 1
        || counts.exact_state_proof_count != 1
    {
        return Err(SelectedRecursiveProverError::ComponentShape(
            "one block requires one claim and one exact-state component",
        ));
    }
    if counts.legacy_proof_count != 0 || counts.legacy_trace_count != 0 {
        return Err(SelectedRecursiveProverError::LegacyAuthorizationCarrier {
            proofs: counts.legacy_proof_count,
            traces: counts.legacy_trace_count,
        });
    }
    if counts.selected_proof_count != counts.authorization_count {
        return Err(
            SelectedRecursiveProverError::AuthorizationProofCardinality {
                expected: counts.authorization_count,
                actual: counts.selected_proof_count,
            },
        );
    }
    if counts.authorization_total != counts.authorization_count {
        return Err(SelectedRecursiveProverError::ComponentShape(
            "authorization total differs from the canonical live prefix",
        ));
    }
    if counts.tx_body_count != counts.authorization_count + 1
        || counts.tx_body_hash_count != counts.tx_body_count
    {
        return Err(SelectedRecursiveProverError::ComponentShape(
            "body spine count differs from coinbase plus live users",
        ));
    }
    Ok(())
}

fn validate_authorization_body_bindings(
    authorization_inputs: &[noid_recursive::block_certificate_backend::AuthorizationComponentInput],
    tx_body_inputs: &[noid_gkr::SpineInputs],
    tx_body_hashes: &[[noid_core::Block128; 2]],
) -> Result<(), SelectedRecursiveProverError> {
    use noid_tx::body_hash::{TX8X2_LEAF_FLAGS, TX8X2_LEAF_INPUT_OWNER};

    let circuit = noid_gkr::SpineCircuit::build();
    for (index, authorization) in authorization_inputs.iter().enumerate() {
        let body_index = index + 1;
        let body = &tx_body_inputs[body_index];
        let body_hash = noid_gkr::compute_tx_body_hash(&circuit, body);
        let flags = body.leaves[TX8X2_LEAF_FLAGS];
        let validity_bitmap = u16::try_from(flags[0].0).ok();
        let live_input_count = validity_bitmap
            .map(|bitmap| (bitmap & ((1u16 << noid_tx::TX_INPUTS) - 1)).count_ones() as u8);
        if authorization.block_index != 0
            || authorization.tx_index != body_index
            || authorization.tx_body_hash != body_hash
            || authorization.public.tx_body_hash != body_hash
            || tx_body_hashes[body_index] != body_hash
            || authorization.public.expected_address != body.leaves[TX8X2_LEAF_INPUT_OWNER]
            || flags[1] != noid_core::Block128::ZERO
            || live_input_count != Some(authorization.live_input_count)
        {
            return Err(SelectedRecursiveProverError::AuthorizationBodyBinding { index });
        }
    }
    Ok(())
}

fn reject_source_commitment_reuse(
    live: &[ZkAuthorizationProof],
    ghost: &ZkAuthorizationProof,
) -> Result<(), SelectedRecursiveProverError> {
    for second in 0..live.len() {
        for first in 0..second {
            if live[first].source_commitment.cap.hashes == live[second].source_commitment.cap.hashes
            {
                return Err(SelectedRecursiveProverError::DuplicateLiveCommitment {
                    first,
                    second,
                });
            }
        }
        if live[second].source_commitment.cap.hashes == ghost.source_commitment.cap.hashes {
            return Err(SelectedRecursiveProverError::LiveGhostCommitmentReuse {
                live_index: second,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::Block128;
    use noid_gkr::owner_auth::{OwnerAuthLayout, OwnerAuthPublicInputs};
    use noid_poseidon2b::primitives::Address;
    use noid_recursive::block_certificate_backend::AuthorizationComponentInput;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    #[test]
    fn dispatches_all_four_canonical_tiers() {
        for (live, expected) in [
            (0, SelectedRecursiveTier::B8),
            (9, SelectedRecursiveTier::B32),
            (33, SelectedRecursiveTier::B64),
            (65, SelectedRecursiveTier::B255),
        ] {
            assert_eq!(selected_recursive_tier(live).unwrap(), expected);
        }
        assert!(matches!(
            selected_recursive_tier(256),
            Err(SelectedRecursiveProverError::NonCanonicalLiveCount { actual: 256 })
        ));
    }

    fn user_body() -> TxBody {
        let owner = Address([0x42; 32]);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 11,
            creation_id: 3,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 9,
            amount: 10,
            owner,
        };
        TxBody {
            epoch_anchor: [3u8; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    #[test]
    fn body_binding_rejects_statement_mismatch_before_recursive_build() {
        let body = user_body();
        let user_spine = noid_gkr::spine_inputs_from_body(&body);
        let circuit = noid_gkr::SpineCircuit::build();
        let hash = noid_gkr::compute_tx_body_hash(&circuit, &user_spine);
        let authorization = AuthorizationComponentInput {
            block_index: 0,
            tx_index: 1,
            tx_body_hash: hash,
            live_input_count: 1,
            public: OwnerAuthPublicInputs {
                layout: OwnerAuthLayout::FIXED,
                tx_body_hash: hash,
                expected_address: body.input_owner.as_fields(),
            },
        };
        let bodies = vec![user_spine.clone(), user_spine];
        let hashes = vec![hash, hash];
        let mut authorizations = vec![authorization];
        validate_authorization_body_bindings(&authorizations, &bodies, &hashes).unwrap();

        authorizations[0].public.expected_address[0] += Block128::ONE;
        assert!(matches!(
            validate_authorization_body_bindings(&authorizations, &bodies, &hashes),
            Err(SelectedRecursiveProverError::AuthorizationBodyBinding { index: 0 })
        ));
    }

    #[test]
    fn carrier_shape_rejects_count_mismatch_and_legacy_vectors() {
        let canonical = SelectedCarrierCounts {
            block_count: 1,
            accepted_claim_count: 1,
            accepted_claim_hash_count: 1,
            legacy_proof_count: 0,
            legacy_trace_count: 0,
            authorization_count: 0,
            selected_proof_count: 1,
            authorization_total: 0,
            tx_body_count: 1,
            tx_body_hash_count: 1,
            legacy_exact_state_count: 1,
            structural_exact_state_count: 1,
            exact_state_proof_count: 1,
        };
        assert!(matches!(
            validate_selected_carrier_counts(canonical),
            Err(
                SelectedRecursiveProverError::AuthorizationProofCardinality {
                    expected: 0,
                    actual: 1
                }
            )
        ));

        let legacy = SelectedCarrierCounts {
            selected_proof_count: 0,
            legacy_proof_count: 1,
            ..canonical
        };
        assert!(matches!(
            validate_selected_carrier_counts(legacy),
            Err(SelectedRecursiveProverError::LegacyAuthorizationCarrier {
                proofs: 1,
                traces: 0
            })
        ));
    }
}
