// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The sole node-owned block-production path.
//!
//! Both the internal miner and `submitBlock(template_id, nonce)` prepare this
//! exact nonce-independent witness before PoW, then consume it once to prove
//! and atomically commit one [`noid_chain::AcceptedBlockBundle`].

use noid_chain::block::Block;
use noid_chain::consensus::pow::{block_id, validate_pow};
use noid_chain::storage::{MdbxChainContext, MdbxContextError};

use crate::template::BlockTemplate;

type HistoryStepRuntime = noid_recursive::acceptance::history_step::HistoryStepRuntime;
type PreparedGhost =
    noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization;
type PreparedStateCommit = noid_chain::consensus::template::PreparedBlockStateCommit;
type LocallyProvedStateCommit = noid_chain::consensus::template::LocallyProvedBlockCommit;

enum PreparedWitness {
    B25(noid_block::PreparedHistoryStepWitness<25>),
    B255(noid_block::PreparedHistoryStepWitness<255>),
}

/// A single-use, nonce-independent block witness prepared entirely by the
/// node. The external PoW worker never receives it and can change only nonce.
pub struct PreparedBlockAttempt {
    block: Block,
    terminal_bytes: Vec<u8>,
    end_accumulator: noid_recursive::ChainAccumulator,
    start_accumulator: noid_recursive::ChainAccumulator,
    parent_header: noid_chain::BlockHeader,
    expected_parent_id: [u8; 32],
    expected_parent_height: u64,
    payload_weight: usize,
    retained_bytes: usize,
    state_commit: PreparedStateCommit,
}

/// A private-capability carrier created only after the HistoryStep prover has
/// successfully produced the exact terminal bundled with `block`.
pub struct ProvedBlock {
    local_commit: LocallyProvedStateCommit,
}

/// The same complete block after its bundle and public state transition have
/// been committed atomically to the canonical chain.
pub struct CommittedBlock {
    block: Block,
    bundle: noid_chain::AcceptedBlockBundle,
}

fn decode_template_authorizations(
    authorization_bytes: Vec<Option<Vec<u8>>>,
) -> Result<Vec<noid_gkr::zk_authorization::ZkAuthorizationProof>, String> {
    authorization_bytes
        .into_iter()
        .enumerate()
        .map(|(index, encoded)| {
            let encoded = encoded.ok_or_else(|| {
                format!("missing wallet authorization for user transaction {index}")
            })?;
            noid_gkr::WalletAuthorizationBundle::from_bytes(&encoded)
                .map(|bundle| bundle.proof)
                .map_err(|error| format!("wallet authorization {index} is not canonical: {error}"))
        })
        .collect()
}

fn accumulator_from_header_boundary(
    header: &noid_chain::BlockHeader,
    epoch_anchor_header: &noid_chain::BlockHeader,
) -> noid_recursive::ChainAccumulator {
    noid_recursive::ChainAccumulator {
        height: header.height,
        tip_semantic_id: noid_chain::block_header::semantic_header_id(header),
        state_root: header.state_root,
        log_slots: header.log_slots,
        active_slot_count: header.active_slot_count,
        alloc_counter: header.alloc_counter,
        epoch_anchor_id: block_id(epoch_anchor_header),
    }
}

impl PreparedBlockAttempt {
    /// Prepare every nonce-independent part of the next HistoryStep.
    pub fn prepare(
        template: BlockTemplate,
        runtime: &HistoryStepRuntime,
        ghost: &PreparedGhost,
        local_time: u64,
    ) -> Result<Self, String> {
        let BlockTemplate {
            inner,
            parent,
            authorization_bytes,
            parent_state,
            finalized_active_counts,
            previous_timestamps,
            asert_anchor,
            parent_tx_epoch_anchor_header,
            parent_history_step_terminal_bytes,
            prepared_state_commit,
            ..
        } = template;

        let expected_parent_id = block_id(&parent);
        let expected_parent_height = parent.height;
        let authorization_weight = authorization_bytes
            .iter()
            .filter_map(|bytes| bytes.as_ref())
            .try_fold(0usize, |total, bytes| total.checked_add(bytes.len()))
            .ok_or_else(|| "prepared authorization byte weight overflow".to_string())?;
        let authorization_proofs = decode_template_authorizations(authorization_bytes)?;
        let start_accumulator =
            accumulator_from_header_boundary(&parent, &parent_tx_epoch_anchor_header);
        let parent_terminal = match (parent.height, parent_history_step_terminal_bytes) {
            (0, None) => None,
            (0, Some(_)) => {
                return Err("genesis parent unexpectedly has a HistoryStep terminal".into());
            }
            (_, Some(bytes)) => Some(
                noid_recursive::acceptance::history_step::decode_history_step_terminal(
                    runtime, &bytes,
                )
                .map_err(|error| format!("parent HistoryStep terminal: {error}"))?,
            ),
            (_, None) => return Err("non-genesis parent HistoryStep terminal is missing".into()),
        };

        let block = inner.into_block(0);
        let payload_weight = block
            .to_bytes()
            .len()
            .checked_add(authorization_weight)
            .ok_or_else(|| "prepared block byte weight overflow".to_string())?;
        let stream = noid_chain::validate_block_page_stream(&block.transactions)
            .map_err(|error| format!("prepared block body is non-canonical: {error}"))?;
        let proof_class = stream.proof_class;
        let context = noid_block::HistoryStepPreparationContext {
            parent_header: &parent,
            tx_epoch_anchor_header: &parent_tx_epoch_anchor_header,
            parent_state: &parent_state,
            start_accumulator: &start_accumulator,
            previous_timestamps: &previous_timestamps,
            finalized_active_counts: &finalized_active_counts,
            asert_anchor: &asert_anchor,
            local_time,
        };
        let witness = match proof_class {
            noid_chain::consensus::paged_spend::BlockProofClass::B25 => {
                noid_block::prepare_history_step_witness::<25>(
                    block,
                    context,
                    authorization_proofs,
                    ghost,
                    runtime,
                    parent_terminal.as_ref(),
                )
                .map(PreparedWitness::B25)
            }
            noid_chain::consensus::paged_spend::BlockProofClass::B255 => {
                noid_block::prepare_history_step_witness::<255>(
                    block,
                    context,
                    authorization_proofs,
                    ghost,
                    runtime,
                    parent_terminal.as_ref(),
                )
                .map(PreparedWitness::B255)
            }
        }
        .map_err(|error| error.to_string())?;

        // The relation is nonce-free: finish the exact template (every native
        // check except PoW) and prove the complete HistoryStep before any
        // nonce search. Post-nonce work is one native PoW check + atomic
        // commit.
        macro_rules! finish_and_prove {
            ($witness:expr) => {{
                let (block, built, end) = $witness
                    .finish_template(runtime)
                    .map_err(|error| error.to_string())?;
                let terminal =
                    noid_recursive::acceptance::history_step::prove_built_history_step_terminal(
                        runtime, &built,
                    )
                    .map_err(|error| error.to_string())?;
                let terminal_bytes =
                    noid_recursive::acceptance::history_step::encode_history_step_terminal(
                        runtime, &terminal,
                    )
                    .map_err(|error| error.to_string())?;
                (block, terminal_bytes, end)
            }};
        }
        let (block, terminal_bytes, end_accumulator) = match witness {
            PreparedWitness::B25(witness) => finish_and_prove!(witness),
            PreparedWitness::B255(witness) => finish_and_prove!(witness),
        };

        let retained_bytes = payload_weight
            .checked_add(terminal_bytes.len())
            .ok_or_else(|| "prepared HistoryStep retained-byte weight overflow".to_string())?;

        Ok(Self {
            block,
            terminal_bytes,
            end_accumulator,
            start_accumulator,
            parent_header: parent,
            expected_parent_id,
            expected_parent_height,
            payload_weight,
            retained_bytes,
            state_commit: prepared_state_commit,
        })
    }

    pub fn pow_header(&self, nonce: u128) -> noid_chain::BlockHeader {
        let mut header = self.block.header;
        header.nonce = nonce;
        header
    }

    pub fn user_page_count(&self) -> usize {
        usize::from(
            noid_chain::validate_block_page_stream(&self.block.transactions)
                .expect("prepared block has a canonical body")
                .page_count,
        )
    }

    pub fn proof_class(&self) -> noid_chain::consensus::paged_spend::BlockProofClass {
        noid_chain::validate_block_page_stream(&self.block.transactions)
            .expect("prepared block has a canonical body")
            .proof_class
    }

    pub const fn expected_parent_id(&self) -> [u8; 32] {
        self.expected_parent_id
    }

    pub const fn expected_parent_height(&self) -> u64 {
        self.expected_parent_height
    }

    /// Consensus-bounded serialized block and authorization payload weight.
    pub const fn payload_weight(&self) -> usize {
        self.payload_weight
    }

    /// Exact block/auth byte weight plus the staged builder's allocated
    /// witness buffer. External lifecycle admission uses this independently
    /// of the consensus payload cap.
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Seal the winning nonce with one native PoW check and create the only
    /// complete network/storage block object.
    ///
    /// The complete HistoryStep terminal was already proven at preparation:
    /// the relation is nonce-free and binds the semantic projection, so it
    /// covers every nonce of this exact template. `runtime` stays in the
    /// signature as the proving-authority witness of the caller's phase.
    pub fn prove(self, _runtime: &HistoryStepRuntime, nonce: u128) -> Result<ProvedBlock, String> {
        let sealed_header = self.pow_header(nonce);
        validate_pow(&sealed_header).map_err(|error| format!("proof of work: {error}"))?;
        let end = self
            .start_accumulator
            .advance(&self.parent_header, &sealed_header)
            .map_err(|error| format!("sealed accumulator transition failed: {error:?}"))?;
        if end != self.end_accumulator {
            return Err("sealed boundary drifted from the proven template".to_string());
        }
        let mut block = self.block;
        block.header.nonce = nonce;
        // SAFETY: `finish_template` performed the complete native consensus
        // checks for this exact template, `validate_pow` above checked the
        // only nonce-dependent rule, and `terminal_bytes` is the canonical
        // encoding of the terminal returned directly by the pinned prover at
        // preparation. The local commit intentionally does not verify its own
        // freshly-authored proof a second time.
        let local_commit = unsafe {
            self.state_commit
                .seal_after_trusted_history_step_proof_unchecked(block, self.terminal_bytes)
        }?;
        Ok(ProvedBlock { local_commit })
    }
}

impl ProvedBlock {
    pub const fn block(&self) -> &Block {
        self.local_commit.block()
    }

    pub const fn bundle(&self) -> &noid_chain::AcceptedBlockBundle {
        self.local_commit.bundle()
    }

    /// Consume the post-prover capability and commit without replaying the
    /// proof that this process has just generated successfully.
    pub fn commit(self, chain: &mut MdbxChainContext) -> Result<CommittedBlock, MdbxContextError> {
        let (block, bundle) = chain.commit_locally_proved_next_block(self.local_commit)?;
        Ok(CommittedBlock { block, bundle })
    }
}

impl CommittedBlock {
    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub const fn bundle(&self) -> &noid_chain::AcceptedBlockBundle {
        &self.bundle
    }

    pub fn into_parts(self) -> (Block, noid_chain::AcceptedBlockBundle) {
        (self.block, self.bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::params::GENESIS_TARGET;
    use noid_poseidon2b::primitives::Address;

    fn header(height: u64, prev_block_hash: [u8; 32]) -> noid_chain::BlockHeader {
        noid_chain::BlockHeader {
            prev_block_hash,
            state_root: [height as u8; 32],
            tx_root: [0x33; 32],
            timestamp: 1_000 + height,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: GENESIS_TARGET,
            log_slots: 24,
            active_slot_count: height,
            alloc_counter: height,
        }
    }

    #[test]
    fn production_boundary_uses_parent_anchor_before_advancing_child_anchor() {
        let genesis = noid_chain::consensus::genesis_header();
        let boundary = header(144, [0x11; 32]);
        let child = header(145, block_id(&boundary));

        let start = accumulator_from_header_boundary(&boundary, &genesis);
        start
            .validate_local_header_boundary(&boundary, &genesis)
            .expect("block 144 terminal still carries the genesis anchor");

        let end = start
            .advance(&boundary, &child)
            .expect("144 -> 145 advances the recursive boundary");
        end.validate_local_header_boundary(&child, &boundary)
            .expect("block 145 terminal carries the derived block-144 anchor");

        let conflated = accumulator_from_header_boundary(&boundary, &boundary);
        assert!(matches!(
            conflated.validate_local_header_boundary(&boundary, &boundary),
            Err(
                noid_recursive::ChainAccumulatorLocalBoundaryError::EpochAnchorHeight {
                    expected: 0,
                    actual: 144,
                }
            )
        ));
    }
}
