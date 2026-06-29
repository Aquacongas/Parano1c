// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Local finalized-history accumulator cache.
//!
//! This object is deliberately not public snapshot authority by itself.  It is
//! the node's incremental finalized-history builder: each finalized block feeds
//! the same 42-field accepted state-transition claim language used by
//! `HistoryProof`, and the cache stores only the current constant-size
//! accumulator state plus small header-anchor metadata.

use crate::accumulator::{genesis_accumulator, ChainAccumulator};
use crate::history_proof::{
    build_history_pcd_step_statement_from_step, build_history_step_statement,
    history_arc_pcd_recursive_base_digest, history_chain_claim_from_digest,
    history_claim_digest_from_fields, history_decider_statement, history_proof_digest,
    prove_history_arc_pcd_recursive_chain_head_step_native,
    prove_history_arc_pcd_recursive_chunk_chain_head_step_native,
    verify_history_arc_pcd_recursive_chain_head_shape_native,
    verify_history_arc_pcd_recursive_chunk_chain_head_shape_native, HistoryAccumulationState,
    HistoryArcPcdAccumulator, HistoryArcPcdRecursiveChainHead,
    HistoryArcPcdRecursiveChunkChainHead, HistoryDeciderProof, HistoryProof, HistoryProofBackend,
    HistoryProofError, HistoryTransitionWitnessItem, HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
    HISTORY_PROOF_VERSION,
};
use noid_chain::consensus::params::GENESIS_TARGET;
use noid_chain::{
    block_work, compute_header_chain_anchor, extend_header_chain_anchor, hash_block_header,
    BlockHeader, HeaderChainAnchor, HeaderChainAnchorError,
};
use noid_core::{Block128, TowerField};
use noid_gkr::HISTORY_CLAIM_FIELDS;
use noid_poseidon2b::primitives::Digest;

pub const LOCAL_HISTORY_CACHE_VERSION: u32 = 2;
pub const LOCAL_HISTORY_RECURSIVE_HEAD_CACHE_VERSION: u32 = 1;
pub const LOCAL_HISTORY_RECURSIVE_CHUNK_HEAD_CACHE_VERSION: u32 = 1;

/// Minimal witness for one accepted block in the local history cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBlockClaimWitness {
    pub claim_fields: [Block128; HISTORY_CLAIM_FIELDS],
    pub claim_digest: Digest,
    pub chain_claim: [Block128; 2],
}

/// Local cache object after a finalized block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalHistoryCache {
    pub version: u32,
    /// Anchor where this finalized-history proof range starts.
    pub start_anchor: HeaderChainAnchor,
    /// Canonical accumulator at `start_anchor`.
    pub start_accumulator: ChainAccumulator,
    /// Current finalized header anchor.  This is rolling metadata, not a second
    /// header store.
    pub anchor: HeaderChainAnchor,
    /// Current accumulation state for the same range.
    pub accumulation_state: HistoryAccumulationState,
    /// Current hash/PCD accumulator instance for the same range.
    pub arc_pcd_accumulator: HistoryArcPcdAccumulator,
    /// Rolling chain accumulator after this block. Kept as a direct field for
    /// existing node status paths; it must equal `accumulation_state.accumulator`.
    pub acc: ChainAccumulator,
    /// Block height covered by `acc`.
    pub block_height: u64,
    /// Canonical accepted-block claim folded into this step.
    pub chain_claim: [Block128; 2],
}

impl LocalHistoryCache {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("LocalHistoryCache serialization is fixed-size")
            .try_into()
            .expect("serialized local history cache length fits usize")
    }

    pub fn proof_byte_len(&self) -> Result<usize, HistoryProofError> {
        Ok(prove_history_from_local_cache(self)?.byte_len())
    }

    pub fn validate_shape(&self) -> Result<(), HistoryProofError> {
        if self.version != LOCAL_HISTORY_CACHE_VERSION {
            return Err(HistoryProofError::UnsupportedVersion {
                version: self.version,
            });
        }
        if self.acc != self.accumulation_state.accumulator
            || self.block_height != self.accumulation_state.height
            || self.anchor.height != self.block_height
            || self.anchor.block_id != self.accumulation_state.block_id
            || self.anchor.state_root != self.acc.state_root
            || self.anchor.projection_root != self.accumulation_state.projection_root
        {
            return Err(HistoryProofError::BadPcdStepState);
        }
        if self.start_accumulator.height != self.start_anchor.height
            || self.start_accumulator.state_root != self.start_anchor.state_root
        {
            return Err(HistoryProofError::StartAccumulatorMismatch);
        }
        if self.arc_pcd_accumulator.step_count != self.accumulation_state.step_count {
            return Err(HistoryProofError::BadStepCount);
        }
        Ok(())
    }
}

/// Proof-worker cache for finalized recursive history.
///
/// This wraps the lightweight local history cache and stores only the current
/// recursive chain head. Updating it is intentionally separate from
/// `advance_local_history_cache`, because proof generation is much heavier than
/// the normal finalized-block accumulator update and should run in a proof
/// worker/background path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalHistoryRecursiveHeadCache {
    pub version: u32,
    pub base: LocalHistoryCache,
    pub recursive_head: Option<HistoryArcPcdRecursiveChainHead>,
}

impl LocalHistoryRecursiveHeadCache {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("LocalHistoryRecursiveHeadCache serialization is fixed-size")
            .try_into()
            .expect("serialized recursive-head cache length fits usize")
    }

    pub fn validate_shape(&self) -> Result<(), HistoryProofError> {
        if self.version != LOCAL_HISTORY_RECURSIVE_HEAD_CACHE_VERSION {
            return Err(HistoryProofError::UnsupportedVersion {
                version: self.version,
            });
        }
        self.base.validate_shape()?;
        let start_state = HistoryAccumulationState::from_anchor(
            &self.base.start_anchor,
            self.base.start_accumulator.clone(),
        )?;
        match (
            self.base.accumulation_state.step_count,
            &self.recursive_head,
        ) {
            (0, None) => Ok(()),
            (0, Some(_)) => Err(HistoryProofError::BadStepCount),
            (_, None) => Err(HistoryProofError::BadStepCount),
            (_, Some(head)) => {
                verify_history_arc_pcd_recursive_chain_head_shape_native(
                    &start_state,
                    &self.base.arc_pcd_accumulator,
                    head,
                )?;
                Ok(())
            }
        }
    }
}

/// Proof-worker cache for finalized recursive history folded in bounded chunks.
///
/// The cache stores no pending headers or witnesses. Callers pass a transient
/// chunk of at most `HISTORY_ARC_PCD_CHUNK_MAX_STEPS` accepted blocks when the
/// proof worker is ready to fold them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalHistoryRecursiveChunkHeadCache {
    pub version: u32,
    pub base: LocalHistoryCache,
    pub recursive_head: Option<HistoryArcPcdRecursiveChunkChainHead>,
}

impl LocalHistoryRecursiveChunkHeadCache {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("LocalHistoryRecursiveChunkHeadCache serialization is fixed-size")
            .try_into()
            .expect("serialized recursive chunk-head cache length fits usize")
    }

    pub fn validate_shape(&self) -> Result<(), HistoryProofError> {
        if self.version != LOCAL_HISTORY_RECURSIVE_CHUNK_HEAD_CACHE_VERSION {
            return Err(HistoryProofError::UnsupportedVersion {
                version: self.version,
            });
        }
        self.base.validate_shape()?;
        let start_state = HistoryAccumulationState::from_anchor(
            &self.base.start_anchor,
            self.base.start_accumulator.clone(),
        )?;
        match (
            self.base.accumulation_state.step_count,
            &self.recursive_head,
        ) {
            (0, None) => Ok(()),
            (0, Some(_)) => Err(HistoryProofError::BadStepCount),
            (_, None) => Err(HistoryProofError::BadStepCount),
            (_, Some(head)) => {
                verify_history_arc_pcd_recursive_chunk_chain_head_shape_native(
                    &start_state,
                    &self.base.arc_pcd_accumulator,
                    head,
                )?;
                Ok(())
            }
        }
    }
}

/// Extend the local finalized-history cache by one block.
pub fn advance_local_history_cache(
    prev_cache: &LocalHistoryCache,
    witness: &AcceptedBlockClaimWitness,
    block_header: &BlockHeader,
    cumulative_chainwork: Digest,
) -> Result<LocalHistoryCache, HistoryProofError> {
    prev_cache.validate_shape()?;
    let anchor = extend_header_chain_anchor(&prev_cache.anchor, block_header, cumulative_chainwork)
        .map_err(map_anchor_error)?;
    let item = HistoryTransitionWitnessItem {
        header: *block_header,
        block_id: anchor.block_id,
        parent_state_root: prev_cache.anchor.state_root,
        child_state_root: block_header.state_root,
        claim_fields: witness.claim_fields,
        chain_claim: witness.chain_claim,
        claim_digest: witness.claim_digest,
    };
    let step = build_history_step_statement(
        &prev_cache.accumulation_state.accumulator,
        prev_cache.accumulation_state.block_id,
        prev_cache.accumulation_state.projection_root,
        &item,
    )?;
    let pcd_step =
        build_history_pcd_step_statement_from_step(&prev_cache.accumulation_state, &step)?;
    let arc_pcd_accumulator = crate::history_proof::advance_history_arc_pcd_accumulator_native(
        &prev_cache.arc_pcd_accumulator,
        &pcd_step,
    )?;
    let accumulation_state = pcd_step.next_state;
    Ok(LocalHistoryCache {
        version: LOCAL_HISTORY_CACHE_VERSION,
        start_anchor: prev_cache.start_anchor.clone(),
        start_accumulator: prev_cache.start_accumulator.clone(),
        anchor,
        arc_pcd_accumulator,
        acc: accumulation_state.accumulator.clone(),
        block_height: accumulation_state.height,
        chain_claim: witness.chain_claim,
        accumulation_state,
    })
}

pub fn init_local_history_recursive_head_cache(
    base: LocalHistoryCache,
) -> Result<LocalHistoryRecursiveHeadCache, HistoryProofError> {
    base.validate_shape()?;
    if base.accumulation_state.step_count != 0 {
        return Err(HistoryProofError::BadStepCount);
    }
    Ok(LocalHistoryRecursiveHeadCache {
        version: LOCAL_HISTORY_RECURSIVE_HEAD_CACHE_VERSION,
        base,
        recursive_head: None,
    })
}

pub fn advance_local_history_recursive_head_cache(
    prev_cache: &LocalHistoryRecursiveHeadCache,
    witness: &AcceptedBlockClaimWitness,
    block_header: &BlockHeader,
    cumulative_chainwork: Digest,
) -> Result<LocalHistoryRecursiveHeadCache, HistoryProofError> {
    prev_cache.validate_shape()?;
    let next_base = advance_local_history_cache(
        &prev_cache.base,
        witness,
        block_header,
        cumulative_chainwork,
    )?;
    let item = HistoryTransitionWitnessItem {
        header: *block_header,
        block_id: next_base.anchor.block_id,
        parent_state_root: prev_cache.base.anchor.state_root,
        child_state_root: block_header.state_root,
        claim_fields: witness.claim_fields,
        chain_claim: witness.chain_claim,
        claim_digest: witness.claim_digest,
    };
    let base_proof_digest = match &prev_cache.recursive_head {
        Some(head) => head.base_proof_digest,
        None => history_arc_pcd_recursive_base_digest(
            &prev_cache.base.accumulation_state,
            &prev_cache.base.arc_pcd_accumulator,
        )?,
    };
    let previous_proof_digest = prev_cache
        .recursive_head
        .as_ref()
        .map(|head| head.final_proof_digest)
        .unwrap_or(base_proof_digest);
    let (next_state, next_accumulator, recursive_head) =
        prove_history_arc_pcd_recursive_chain_head_step_native(
            base_proof_digest,
            previous_proof_digest,
            &prev_cache.base.arc_pcd_accumulator,
            &prev_cache.base.accumulation_state,
            &item,
        )?;
    if next_state != next_base.accumulation_state
        || next_accumulator != next_base.arc_pcd_accumulator
    {
        return Err(HistoryProofError::BadPcdStepState);
    }

    Ok(LocalHistoryRecursiveHeadCache {
        version: LOCAL_HISTORY_RECURSIVE_HEAD_CACHE_VERSION,
        base: next_base,
        recursive_head: Some(recursive_head),
    })
}

pub fn init_local_history_recursive_chunk_head_cache(
    base: LocalHistoryCache,
) -> Result<LocalHistoryRecursiveChunkHeadCache, HistoryProofError> {
    base.validate_shape()?;
    if base.accumulation_state.step_count != 0 {
        return Err(HistoryProofError::BadStepCount);
    }
    Ok(LocalHistoryRecursiveChunkHeadCache {
        version: LOCAL_HISTORY_RECURSIVE_CHUNK_HEAD_CACHE_VERSION,
        base,
        recursive_head: None,
    })
}

pub fn advance_local_history_recursive_chunk_head_cache(
    prev_cache: &LocalHistoryRecursiveChunkHeadCache,
    witnesses: &[AcceptedBlockClaimWitness],
    block_headers: &[BlockHeader],
    cumulative_chainworks: &[Digest],
) -> Result<LocalHistoryRecursiveChunkHeadCache, HistoryProofError> {
    prev_cache.validate_shape()?;
    if witnesses.is_empty()
        || witnesses.len() > HISTORY_ARC_PCD_CHUNK_MAX_STEPS
        || witnesses.len() != block_headers.len()
        || witnesses.len() != cumulative_chainworks.len()
    {
        return Err(HistoryProofError::BadStepCount);
    }

    let mut next_base = prev_cache.base.clone();
    let mut items = Vec::with_capacity(witnesses.len());
    for ((witness, block_header), cumulative_chainwork) in witnesses
        .iter()
        .zip(block_headers.iter())
        .zip(cumulative_chainworks.iter())
    {
        let parent_state_root = next_base.anchor.state_root;
        let next_step_base =
            advance_local_history_cache(&next_base, witness, block_header, *cumulative_chainwork)?;
        items.push(HistoryTransitionWitnessItem {
            header: *block_header,
            block_id: next_step_base.anchor.block_id,
            parent_state_root,
            child_state_root: block_header.state_root,
            claim_fields: witness.claim_fields,
            chain_claim: witness.chain_claim,
            claim_digest: witness.claim_digest,
        });
        next_base = next_step_base;
    }

    let base_proof_digest = match &prev_cache.recursive_head {
        Some(head) => head.base_proof_digest,
        None => history_arc_pcd_recursive_base_digest(
            &prev_cache.base.accumulation_state,
            &prev_cache.base.arc_pcd_accumulator,
        )?,
    };
    let previous_proof_digest = prev_cache
        .recursive_head
        .as_ref()
        .map(|head| head.final_proof_digest)
        .unwrap_or(base_proof_digest);
    let previous_chunk_count = prev_cache
        .recursive_head
        .as_ref()
        .map(|head| head.chunk_count)
        .unwrap_or(0);
    let (next_state, next_accumulator, recursive_head) =
        prove_history_arc_pcd_recursive_chunk_chain_head_step_native(
            base_proof_digest,
            previous_proof_digest,
            previous_chunk_count,
            &prev_cache.base.arc_pcd_accumulator,
            &prev_cache.base.accumulation_state,
            &items,
        )?;
    if next_state != next_base.accumulation_state
        || next_accumulator != next_base.arc_pcd_accumulator
    {
        return Err(HistoryProofError::BadPcdStepState);
    }

    Ok(LocalHistoryRecursiveChunkHeadCache {
        version: LOCAL_HISTORY_RECURSIVE_CHUNK_HEAD_CACHE_VERSION,
        base: next_base,
        recursive_head: Some(recursive_head),
    })
}

/// Produce the local cache entry for genesis using production genesis work.
pub fn init_genesis_history_cache() -> LocalHistoryCache {
    init_genesis_history_cache_with_chainwork(block_work(&GENESIS_TARGET))
}

/// Produce the local cache entry for genesis with an explicit chainwork value.
pub fn init_genesis_history_cache_with_chainwork(
    cumulative_chainwork: Digest,
) -> LocalHistoryCache {
    use noid_chain::consensus::genesis::genesis_header;

    let genesis = genesis_header();
    let block_hash = hash_block_header(&genesis);
    let anchor = compute_header_chain_anchor([genesis].iter(), cumulative_chainwork)
        .expect("genesis anchor");
    let start_accumulator = genesis_accumulator(genesis.state_root, block_hash);
    init_local_history_cache_from_anchor(anchor, start_accumulator)
        .expect("genesis local history cache")
}

pub fn init_local_history_cache_from_anchor(
    anchor: HeaderChainAnchor,
    start_accumulator: ChainAccumulator,
) -> Result<LocalHistoryCache, HistoryProofError> {
    let accumulation_state =
        HistoryAccumulationState::from_anchor(&anchor, start_accumulator.clone())?;
    let arc_pcd_accumulator = HistoryArcPcdAccumulator::from_start_state(&accumulation_state)?;
    let block_height = accumulation_state.height;
    Ok(LocalHistoryCache {
        version: LOCAL_HISTORY_CACHE_VERSION,
        start_anchor: anchor.clone(),
        start_accumulator: start_accumulator.clone(),
        anchor,
        accumulation_state,
        arc_pcd_accumulator,
        acc: start_accumulator,
        block_height,
        chain_claim: [Block128::ZERO; 2],
    })
}

/// Empty witness for tests that explicitly cover the all-zero claim schedule.
pub fn empty_accepted_block_witness() -> AcceptedBlockClaimWitness {
    accepted_block_claim_witness_from_fields([Block128::ZERO; HISTORY_CLAIM_FIELDS])
        .expect("zero claim witness is well-formed")
}

/// Build a local-history witness from the full 42-field history claim schedule.
pub fn accepted_block_claim_witness_from_fields(
    claim_fields: [Block128; HISTORY_CLAIM_FIELDS],
) -> Result<AcceptedBlockClaimWitness, HistoryProofError> {
    let claim_digest = history_claim_digest_from_fields(&claim_fields);
    Ok(AcceptedBlockClaimWitness {
        claim_fields,
        claim_digest,
        chain_claim: history_chain_claim_from_digest(&claim_digest),
    })
}

/// Build a constant-size native history proof from the current finalized cache.
///
/// This avoids replaying the covered history when serving the local proof
/// envelope.  The untrusted verifier still rejects `NativeFoldV1` until the
/// final recursive backend verifier is active.
pub fn prove_history_from_local_cache(
    cache: &LocalHistoryCache,
) -> Result<HistoryProof, HistoryProofError> {
    cache.validate_shape()?;
    let mut proof = HistoryProof {
        version: HISTORY_PROOF_VERSION,
        backend: HistoryProofBackend::NativeFoldV1,
        start_anchor: cache.start_anchor.clone(),
        end_anchor: cache.anchor.clone(),
        start_accumulator: cache.start_accumulator.clone(),
        end_accumulator: cache.acc.clone(),
        folded_witness_root: cache.accumulation_state.folded_witness_root,
        step_count: cache.accumulation_state.step_count,
        decider: HistoryDeciderProof::zero(),
        proof_digest: [0u8; 32],
    };
    let statement = history_decider_statement(&proof);
    proof.decider = HistoryDeciderProof::native_fold_v1(&statement, &cache.arc_pcd_accumulator)?;
    proof.proof_digest = history_proof_digest(&proof);
    Ok(proof)
}

pub fn prove_history_arc_pcd_from_recursive_head_cache(
    cache: &LocalHistoryRecursiveHeadCache,
) -> Result<HistoryProof, HistoryProofError> {
    cache.validate_shape()?;
    let Some(recursive_head) = cache.recursive_head.clone() else {
        return Err(HistoryProofError::BadStepCount);
    };
    let mut proof = HistoryProof {
        version: HISTORY_PROOF_VERSION,
        backend: HistoryProofBackend::ArcPcdV1,
        start_anchor: cache.base.start_anchor.clone(),
        end_anchor: cache.base.anchor.clone(),
        start_accumulator: cache.base.start_accumulator.clone(),
        end_accumulator: cache.base.acc.clone(),
        folded_witness_root: cache.base.accumulation_state.folded_witness_root,
        step_count: cache.base.accumulation_state.step_count,
        decider: HistoryDeciderProof::zero(),
        proof_digest: [0u8; 32],
    };
    let statement = history_decider_statement(&proof);
    proof.decider = HistoryDeciderProof::arc_pcd_recursive_head_v1(
        &statement,
        &cache.base.arc_pcd_accumulator,
        recursive_head,
    )?;
    proof.proof_digest = history_proof_digest(&proof);
    Ok(proof)
}

pub fn prove_history_arc_pcd_from_recursive_chunk_head_cache(
    cache: &LocalHistoryRecursiveChunkHeadCache,
) -> Result<HistoryProof, HistoryProofError> {
    cache.validate_shape()?;
    let Some(recursive_chunk_head) = cache.recursive_head.clone() else {
        return Err(HistoryProofError::BadStepCount);
    };
    let mut proof = HistoryProof {
        version: HISTORY_PROOF_VERSION,
        backend: HistoryProofBackend::ArcPcdV1,
        start_anchor: cache.base.start_anchor.clone(),
        end_anchor: cache.base.anchor.clone(),
        start_accumulator: cache.base.start_accumulator.clone(),
        end_accumulator: cache.base.acc.clone(),
        folded_witness_root: cache.base.accumulation_state.folded_witness_root,
        step_count: cache.base.accumulation_state.step_count,
        decider: HistoryDeciderProof::zero(),
        proof_digest: [0u8; 32],
    };
    let statement = history_decider_statement(&proof);
    proof.decider = HistoryDeciderProof::arc_pcd_recursive_chunk_head_v1(
        &statement,
        &cache.base.arc_pcd_accumulator,
        recursive_chunk_head,
    )?;
    proof.proof_digest = history_proof_digest(&proof);
    Ok(proof)
}

fn map_anchor_error(error: HeaderChainAnchorError) -> HistoryProofError {
    match error {
        HeaderChainAnchorError::NonContiguous { expected, actual } => {
            HistoryProofError::BadWitnessHeight { expected, actual }
        }
        HeaderChainAnchorError::BadParentLink { height } => {
            HistoryProofError::BadWitnessParentBlock { height }
        }
        HeaderChainAnchorError::Empty | HeaderChainAnchorError::StartsAfterGenesis { .. } => {
            HistoryProofError::BadHeaderProjectionRoot
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history_proof::{verify_history_proof_native, verify_history_proof_untrusted};
    use noid_chain::consensus::genesis::{genesis_header, genesis_state_root};
    use noid_chain::header_anchor::extend_header_projection_root;
    use noid_poseidon2b::primitives::Address;

    fn header(height: u64, parent: &HeaderChainAnchor, state_seed: u8) -> BlockHeader {
        BlockHeader {
            prev_block_hash: parent.block_id,
            state_root: [state_seed; 32],
            tx_root: [state_seed ^ 0x55; 32],
            timestamp: 1_700_000_000 + height,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: GENESIS_TARGET,
            log_slots: 24,
            active_slot_count: height,
            alloc_counter: height * 2,
        }
    }

    fn claim(
        height: u64,
        block_id: Digest,
        parent: &HeaderChainAnchor,
        child_state_root: Digest,
    ) -> AcceptedBlockClaimWitness {
        let mut fields = [Block128::ZERO; HISTORY_CLAIM_FIELDS];
        fields[0] = Block128::from(HISTORY_PROOF_VERSION as u128);
        fields[1] = Block128::from(height as u128);
        write_digest_fields(&mut fields, 2, &block_id);
        write_digest_fields(&mut fields, 4, &parent.block_id);
        write_digest_fields(&mut fields, 6, &parent.state_root);
        write_digest_fields(&mut fields, 8, &child_state_root);
        accepted_block_claim_witness_from_fields(fields).expect("claim witness")
    }

    fn write_digest_fields(
        fields: &mut [Block128; HISTORY_CLAIM_FIELDS],
        idx: usize,
        digest: &Digest,
    ) {
        fields[idx] = Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap()));
        fields[idx + 1] = Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap()));
    }

    #[test]
    fn genesis_local_history_cache_has_correct_accumulator() {
        let cache = init_genesis_history_cache();

        let genesis = genesis_header();
        let genesis_hash = hash_block_header(&genesis);
        let expected_acc = genesis_accumulator(genesis_state_root(), genesis_hash);

        cache.validate_shape().expect("cache shape");
        assert_eq!(cache.version, LOCAL_HISTORY_CACHE_VERSION);
        assert_eq!(cache.block_height, 0, "genesis cache must be at height 0");
        assert_eq!(cache.acc.chain_hash, expected_acc.chain_hash);
        assert_eq!(cache.acc.state_root, genesis.state_root);
        assert_eq!(cache.chain_claim, [Block128::ZERO; 2]);
    }

    #[test]
    fn accepted_block_claim_witness_derives_chain_claim_from_full_fields() {
        let mut fields = [Block128::ZERO; HISTORY_CLAIM_FIELDS];
        fields[0] = Block128::from(HISTORY_PROOF_VERSION as u128);
        fields[1] = Block128::from(7u128);
        let witness = accepted_block_claim_witness_from_fields(fields).expect("witness");
        assert_eq!(
            witness.chain_claim,
            history_chain_claim_from_digest(&witness.claim_digest)
        );
    }

    #[test]
    fn local_history_cache_advances_history_state_and_serves_constant_proof() {
        let mut cache = init_genesis_history_cache();
        let genesis = genesis_header();
        let mut expected_projection =
            extend_header_projection_root(&[0u8; 32], &genesis, &hash_block_header(&genesis));

        for height in 1..=3 {
            let child = header(height, &cache.anchor, height as u8 + 1);
            let child_id = hash_block_header(&child);
            let witness = claim(height, child_id, &cache.anchor, child.state_root);
            let chainwork = noid_chain::add_work(
                &cache.anchor.cumulative_chainwork,
                &block_work(&child.difficulty_target),
            );
            expected_projection =
                extend_header_projection_root(&expected_projection, &child, &child_id);
            cache = advance_local_history_cache(&cache, &witness, &child, chainwork)
                .expect("advance cache");
            assert_eq!(cache.anchor.projection_root, expected_projection);
            assert_eq!(cache.block_height, height);
            assert_eq!(cache.accumulation_state.step_count, height);
            let proof = prove_history_from_local_cache(&cache).expect("cache proof");
            verify_history_proof_native(&proof, &cache.start_anchor, &cache.anchor)
                .expect("native proof verifies");
            assert_eq!(proof.byte_len(), cache.proof_byte_len().unwrap());
        }
    }

    #[test]
    fn recursive_head_cache_advances_without_changing_base_cache_shape() {
        let mut base_cache = init_genesis_history_cache();
        let mut recursive_cache =
            init_local_history_recursive_head_cache(base_cache.clone()).expect("recursive cache");
        assert!(recursive_cache.recursive_head.is_none());
        recursive_cache.validate_shape().expect("genesis shape");
        let mut recursive_cache_len = None;

        for height in 1..=3 {
            let child = header(height, &base_cache.anchor, height as u8 + 1);
            let child_id = hash_block_header(&child);
            let witness = claim(height, child_id, &base_cache.anchor, child.state_root);
            let chainwork = noid_chain::add_work(
                &base_cache.anchor.cumulative_chainwork,
                &block_work(&child.difficulty_target),
            );
            base_cache = advance_local_history_cache(&base_cache, &witness, &child, chainwork)
                .expect("advance base cache");
            recursive_cache = advance_local_history_recursive_head_cache(
                &recursive_cache,
                &witness,
                &child,
                chainwork,
            )
            .expect("advance recursive cache");

            assert_eq!(recursive_cache.base, base_cache);
            recursive_cache.validate_shape().expect("recursive shape");
            let head = recursive_cache
                .recursive_head
                .as_ref()
                .expect("recursive head");
            assert_eq!(head.step_count, height);
            assert_eq!(
                head.step_count,
                recursive_cache.base.accumulation_state.step_count
            );
            if let Some(expected) = recursive_cache_len {
                assert_eq!(recursive_cache.byte_len(), expected);
            } else {
                recursive_cache_len = Some(recursive_cache.byte_len());
            }
        }
    }

    #[test]
    fn recursive_head_cache_rejects_tampered_head() {
        let base_cache = init_genesis_history_cache();
        let child = header(1, &base_cache.anchor, 2);
        let child_id = hash_block_header(&child);
        let witness = claim(1, child_id, &base_cache.anchor, child.state_root);
        let chainwork = noid_chain::add_work(
            &base_cache.anchor.cumulative_chainwork,
            &block_work(&child.difficulty_target),
        );
        let recursive_cache =
            init_local_history_recursive_head_cache(base_cache).expect("recursive cache");
        let mut recursive_cache = advance_local_history_recursive_head_cache(
            &recursive_cache,
            &witness,
            &child,
            chainwork,
        )
        .expect("advance recursive cache");
        recursive_cache
            .recursive_head
            .as_mut()
            .expect("recursive head")
            .final_step_proof
            .recursive_hashes
            .n_fields += 2;

        assert_eq!(
            recursive_cache.validate_shape(),
            Err(HistoryProofError::BadDeciderHashProof)
        );
    }

    #[test]
    fn recursive_head_cache_serves_arc_pcd_proof_shape_but_untrusted_fails_closed() {
        let mut recursive_cache =
            init_local_history_recursive_head_cache(init_genesis_history_cache())
                .expect("recursive cache");
        let mut expected_len = None;

        for height in 1..=3 {
            let child = header(height, &recursive_cache.base.anchor, height as u8 + 1);
            let child_id = hash_block_header(&child);
            let witness = claim(
                height,
                child_id,
                &recursive_cache.base.anchor,
                child.state_root,
            );
            let chainwork = noid_chain::add_work(
                &recursive_cache.base.anchor.cumulative_chainwork,
                &block_work(&child.difficulty_target),
            );
            recursive_cache = advance_local_history_recursive_head_cache(
                &recursive_cache,
                &witness,
                &child,
                chainwork,
            )
            .expect("advance recursive cache");

            if height == 1 {
                continue;
            }

            let proof = prove_history_arc_pcd_from_recursive_head_cache(&recursive_cache)
                .expect("recursive-head proof");
            verify_history_proof_native(
                &proof,
                &recursive_cache.base.start_anchor,
                &recursive_cache.base.anchor,
            )
            .expect("native staged proof verifies");
            assert_eq!(
                verify_history_proof_untrusted(
                    &proof,
                    &recursive_cache.base.start_anchor,
                    &recursive_cache.base.anchor,
                ),
                Err(HistoryProofError::BackendVerifierMissing)
            );
            assert!(proof.decider.recursive_head.is_some());
            assert!(proof.decider.one_step_proof.is_none());
            assert!(proof.decider.hash_proofs.is_none());
            if let Some(expected) = expected_len {
                assert_eq!(proof.byte_len(), expected);
            } else {
                expected_len = Some(proof.byte_len());
            }
        }
    }

    #[test]
    fn recursive_chunk_head_cache_advances_bounded_chunks_without_changing_base_shape() {
        let mut base_cache = init_genesis_history_cache();
        let mut chunk_cache =
            init_local_history_recursive_chunk_head_cache(base_cache.clone()).expect("chunk cache");
        assert!(chunk_cache.recursive_head.is_none());
        chunk_cache.validate_shape().expect("genesis chunk shape");
        let mut chunk_cache_len = None;
        let mut expected_chunk_count = 0u64;

        for chunk_len in [1usize, 3, 2] {
            let mut witnesses = Vec::with_capacity(chunk_len);
            let mut headers = Vec::with_capacity(chunk_len);
            let mut chainworks = Vec::with_capacity(chunk_len);
            let mut expected_base = base_cache.clone();

            for offset in 0..chunk_len {
                let height = expected_base.block_height + 1;
                let child = header(height, &expected_base.anchor, 10 + offset as u8);
                let child_id = hash_block_header(&child);
                let witness = claim(height, child_id, &expected_base.anchor, child.state_root);
                let chainwork = noid_chain::add_work(
                    &expected_base.anchor.cumulative_chainwork,
                    &block_work(&child.difficulty_target),
                );
                expected_base =
                    advance_local_history_cache(&expected_base, &witness, &child, chainwork)
                        .expect("advance expected base");
                witnesses.push(witness);
                headers.push(child);
                chainworks.push(chainwork);
            }

            chunk_cache = advance_local_history_recursive_chunk_head_cache(
                &chunk_cache,
                &witnesses,
                &headers,
                &chainworks,
            )
            .expect("advance chunk cache");
            base_cache = expected_base;
            assert_eq!(chunk_cache.base, base_cache);
            chunk_cache.validate_shape().expect("chunk cache shape");
            let head = chunk_cache
                .recursive_head
                .as_ref()
                .expect("recursive chunk head");
            assert_eq!(
                head.step_count,
                chunk_cache.base.accumulation_state.step_count
            );
            expected_chunk_count += 1;
            assert_eq!(head.chunk_count, expected_chunk_count);
            if let Some(expected) = chunk_cache_len {
                assert_eq!(chunk_cache.byte_len(), expected);
            } else {
                chunk_cache_len = Some(chunk_cache.byte_len());
            }
        }
    }

    #[test]
    fn recursive_chunk_head_cache_rejects_bad_chunks_and_tamper() {
        let base_cache = init_genesis_history_cache();
        let mut chunk_cache =
            init_local_history_recursive_chunk_head_cache(base_cache.clone()).expect("chunk cache");
        assert_eq!(
            advance_local_history_recursive_chunk_head_cache(&chunk_cache, &[], &[], &[]),
            Err(HistoryProofError::BadStepCount)
        );

        let child = header(1, &base_cache.anchor, 2);
        let child_id = hash_block_header(&child);
        let witness = claim(1, child_id, &base_cache.anchor, child.state_root);
        let chainwork = noid_chain::add_work(
            &base_cache.anchor.cumulative_chainwork,
            &block_work(&child.difficulty_target),
        );
        assert_eq!(
            advance_local_history_recursive_chunk_head_cache(
                &chunk_cache,
                std::slice::from_ref(&witness),
                std::slice::from_ref(&child),
                &[],
            ),
            Err(HistoryProofError::BadStepCount)
        );

        chunk_cache = advance_local_history_recursive_chunk_head_cache(
            &chunk_cache,
            &[witness],
            &[child],
            &[chainwork],
        )
        .expect("advance chunk cache");
        chunk_cache
            .recursive_head
            .as_mut()
            .expect("recursive chunk head")
            .final_chunk_proof
            .recursive_hashes
            .n_fields += 2;
        assert_eq!(
            chunk_cache.validate_shape(),
            Err(HistoryProofError::BadDeciderHashProof)
        );
    }

    #[test]
    fn recursive_chunk_head_cache_serves_arc_pcd_proof_shape_but_untrusted_fails_closed() {
        let mut chunk_cache =
            init_local_history_recursive_chunk_head_cache(init_genesis_history_cache())
                .expect("chunk cache");
        let mut expected_len = None;

        for chunk_len in [1usize, 3, 2] {
            let mut witnesses = Vec::with_capacity(chunk_len);
            let mut headers = Vec::with_capacity(chunk_len);
            let mut chainworks = Vec::with_capacity(chunk_len);
            let mut parent_anchor = chunk_cache.base.anchor.clone();

            for offset in 0..chunk_len {
                let height = parent_anchor.height + 1;
                let child = header(height, &parent_anchor, 20 + offset as u8);
                let child_id = hash_block_header(&child);
                let witness = claim(height, child_id, &parent_anchor, child.state_root);
                let chainwork = noid_chain::add_work(
                    &parent_anchor.cumulative_chainwork,
                    &block_work(&child.difficulty_target),
                );
                parent_anchor =
                    extend_header_chain_anchor(&parent_anchor, &child, chainwork).expect("anchor");
                witnesses.push(witness);
                headers.push(child);
                chainworks.push(chainwork);
            }

            chunk_cache = advance_local_history_recursive_chunk_head_cache(
                &chunk_cache,
                &witnesses,
                &headers,
                &chainworks,
            )
            .expect("advance chunk cache");

            let proof = prove_history_arc_pcd_from_recursive_chunk_head_cache(&chunk_cache)
                .expect("recursive chunk-head proof");
            verify_history_proof_native(
                &proof,
                &chunk_cache.base.start_anchor,
                &chunk_cache.base.anchor,
            )
            .expect("native chunk-head proof verifies");
            assert_eq!(
                verify_history_proof_untrusted(
                    &proof,
                    &chunk_cache.base.start_anchor,
                    &chunk_cache.base.anchor,
                ),
                Err(HistoryProofError::BackendVerifierMissing)
            );
            assert!(proof.decider.recursive_chunk_head.is_some());
            assert!(proof.decider.recursive_head.is_none());
            assert!(proof.decider.one_step_proof.is_none());
            assert!(proof.decider.hash_proofs.is_none());
            if let Some(expected) = expected_len {
                assert_eq!(proof.byte_len(), expected);
            } else {
                expected_len = Some(proof.byte_len());
            }
        }
    }

    #[test]
    fn local_history_cache_rejects_claim_fields_not_bound_to_header() {
        let cache = init_genesis_history_cache();
        let child = header(1, &cache.anchor, 2);
        let child_id = hash_block_header(&child);
        let bad_child_state_root = [0x99; 32];
        let witness = claim(1, child_id, &cache.anchor, bad_child_state_root);
        let chainwork = noid_chain::add_work(
            &cache.anchor.cumulative_chainwork,
            &block_work(&child.difficulty_target),
        );

        assert_eq!(
            advance_local_history_cache(&cache, &witness, &child, chainwork),
            Err(HistoryProofError::BadStepClaimFields)
        );
    }
}
