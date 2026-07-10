// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `MdbxChainContext` — crash-consistent chain context backed by MDBX.
//!
//! Replaces the in-memory `ChainContext` with a version that survives process
//! restarts. The consensus logic is reused unchanged; only the
//! persistence layer differs.
//!
//! # Crash-consistency guarantee (P.18)
//!
//! Every `apply_next_block` call writes all block data in ONE atomic MDBX
//! transaction. Either the full block is committed or nothing is. On restart,
//! `open_or_create` reads `chain_tip` from MDBX and rebuilds hot RAM state
//! from the `segments` table. No replay from genesis needed.
//!
//! # Restart strategy
//!
//! On startup, the node attempts to resume from persisted state. If the
//! state_root integrity check passes (segment columns produce the expected
//! root), the node resumes at its stored tip height and forward-syncs from
//! peers (block-by-block for small gaps, snapshot-sync for large gaps).
//!
//! If persisted state cannot be restored, every chain table is cleared before
//! the canonical genesis is installed. Mixed-epoch recovery is never attempted.
//!
//! This prevents simultaneous-restart network death: when all nodes reboot,
//! each resumes from its own verified state instead of needing a peer snapshot.
//!
//! # Hot vs cold data
//!
//! | Data | Where | Why |
//! |------|-------|-----|
//! | Headers | MDBX (forever) | Random access by height/hash |
//! | Segment columns | MDBX (forever) | Persist across restarts |
//! | Undo logs | MDBX retained window | Reorg recovery |
//! | Block bodies/proofs/sidecars | MDBX retained suffix after coverage | Bounded peer sync and prover input |
//! | ChainState (active/alloc) | MDBX (state_meta) | Fast restart |
//! | Recent headers | RAM (MEDIAN_TIME_BLOCKS + ANCHOR_DEPTH) | Timestamp + anchor validation |

use std::collections::HashMap;
use std::path::Path;

use crate::block::{apply_state_delta, Block};
use crate::block_header::BlockHeader;
use crate::chain_context::ChainContext;
use crate::checkpoint::{
    checkpoint_payload_root, CheckpointCoverage, CheckpointSegmentPayload,
    ImmutableCheckpointManifest, ImmutableCheckpointPackage, CHECKPOINT_AUTH_SIDECAR_ROOT_DOMAIN,
    CHECKPOINT_BLOCK_BODY_ROOT_DOMAIN, CHECKPOINT_BLOCK_PROOF_ROOT_DOMAIN,
    CHECKPOINT_SEGMENT_PAYLOAD_ROOT_DOMAIN,
};
use crate::consensus::{
    da_prune::{build_undo_log, revert_block},
    difficulty::{add_work, block_work},
    header::epoch_anchor_height,
    params::{
        ANCHOR_DEPTH, CONSENSUS_FINALITY_DEPTH, EXPANSION_WINDOW, GENESIS_TARGET,
        MEDIAN_TIME_BLOCKS,
    },
    pow::block_id,
    validation::{validate_block_checks, AnchorInfo},
    ConsensusError,
};
use crate::segmented_state::SegmentedFriState;
use crate::state::ChainState;
use crate::storage::serial::encode_segment;
use crate::storage::{ConsensusMeta, FinalizedCheckpoint, MdbxStore, StoreError};
use noid_poseidon2b::primitives::TxBodyHash;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum MdbxContextError {
    Store(StoreError),
    Consensus(ConsensusError),
    Corrupt(&'static str),
}

impl std::fmt::Display for MdbxContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Consensus(e) => write!(f, "consensus: {e}"),
            Self::Corrupt(msg) => write!(f, "corrupt: {msg}"),
        }
    }
}
impl std::error::Error for MdbxContextError {}

impl From<StoreError> for MdbxContextError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<ConsensusError> for MdbxContextError {
    fn from(e: ConsensusError) -> Self {
        Self::Consensus(e)
    }
}

// ---------------------------------------------------------------------------
// MdbxChainContext
// ---------------------------------------------------------------------------

/// Crash-consistent chain context backed by MDBX.
///
/// On startup: reads tip from MDBX, loads all segment columns, rebuilds
/// loads recent headers.
///
/// On each block: writes all data atomically, then updates hot RAM state.
pub struct MdbxChainContext {
    /// MDBX database (all durable storage).
    pub store: MdbxStore,

    /// Hot in-memory UTXO state (rebuilt from MDBX on startup, updated on each block).
    /// `state.state` is a `SegmentedFriState` whose dirty segments are written to MDBX
    /// atomically with each block commit.
    pub state: ChainState,

    /// Recent headers for validation (needed for MTP, ASERT anchor, epoch_anchor check).
    /// Covers the last `MEDIAN_TIME_BLOCKS + ANCHOR_DEPTH` blocks.
    pub recent_headers: HashMap<u64, BlockHeader>,

    /// Current tip height.
    pub tip_height: u64,

    /// H_BLOCK of the current tip.
    pub tip_hash: [u8; 32],

    /// Cumulative PoW work for the current tip chain.
    /// Sum of block_work(difficulty_target) for all blocks from genesis to tip.
    /// Used as the primary fork choice criterion (more work = canonical chain).
    pub tip_chain_work: [u8; 32],

    /// Non-optional hard-finalized canonical checkpoint.
    pub finalized: FinalizedCheckpoint,

    /// Internal guard used during batch reorg application: finality is advanced
    /// only after the whole replacement branch has been applied successfully.
    defer_finality_updates: bool,
}

impl MdbxChainContext {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Open an existing MDBX database, or initialise a fresh one from genesis.
    ///
    /// State persistence strategy:
    ///
    /// 1. If MDBX has valid state (chain_tip + segments with correct state_root),
    ///    resume from local state. The P2P layer handles forward-sync (block-by-block
    ///    if gap <= CONSENSUS_FINALITY_DEPTH, snapshot-sync if gap is larger).
    ///
    /// 2. If state cannot be restored, atomically clear every chain table and
    ///    initialise the canonical genesis. No format migration is attempted.
    ///
    /// 3. If MDBX is empty (first run), initialise from genesis.
    ///
    /// This prevents simultaneous-restart network death: when all nodes reboot at
    /// once (provider outage), each resumes from its own verified local state instead
    /// of requiring peers to serve a snapshot that nobody has.
    ///
    pub fn open_or_create(path: &Path) -> Result<Self, MdbxContextError> {
        let store = MdbxStore::open(path)?;

        if store.is_empty()? {
            // First run: initialise from genesis.
            let consensus = ChainContext::init_from_genesis();
            let tip_chain_work = block_work(&GENESIS_TARGET);
            let finalized = FinalizedCheckpoint {
                height: 0,
                hash: consensus.tip_hash,
            };
            let ctx = Self {
                store,
                state: consensus.state,
                recent_headers: consensus.headers,
                tip_height: consensus.tip_height,
                tip_hash: consensus.tip_hash,
                tip_chain_work,
                finalized,
                defer_finality_updates: false,
            };
            ctx.persist_genesis()?;
            Ok(ctx)
        } else {
            // Try to restore from existing MDBX state (state_root integrity check inside).
            match Self::restore_from_mdbx(store) {
                Ok(ctx) => {
                    tracing::info!(height = ctx.tip_height, "resumed from persisted state");
                    Ok(ctx)
                }
                Err(MdbxContextError::Corrupt(reason)) => {
                    tracing::warn!(
                        reason,
                        "persisted state rejected — clearing the chain database"
                    );
                    // Re-open store (the previous one was consumed by restore_from_mdbx).
                    let store = MdbxStore::open(path)?;
                    store.clear_all()?;
                    let consensus = ChainContext::init_from_genesis();
                    let tip_chain_work = block_work(&GENESIS_TARGET);
                    let finalized = FinalizedCheckpoint {
                        height: 0,
                        hash: consensus.tip_hash,
                    };
                    let ctx = Self {
                        store,
                        state: consensus.state,
                        recent_headers: consensus.headers,
                        tip_height: consensus.tip_height,
                        tip_hash: consensus.tip_hash,
                        tip_chain_work,
                        finalized,
                        defer_finality_updates: false,
                    };
                    ctx.persist_genesis()?;
                    Ok(ctx)
                }
                Err(e) => Err(e),
            }
        }
    }

    /// Test-only: open a fresh MDBX with a trivially-satisfiable genesis
    /// (difficulty_target = `[0xFF;32]`).  All subsequent blocks can use nonce=0,
    /// so no PoW search is needed in tests that are testing storage logic.
    #[cfg(test)]
    fn open_or_create_for_test(path: &std::path::Path) -> Result<Self, MdbxContextError> {
        use crate::chain_context::TEST_TARGET;
        let store = MdbxStore::open(path)?;
        if store.is_empty()? {
            let consensus = ChainContext::init_from_easy_genesis();
            let tip_chain_work = crate::block_work(&TEST_TARGET);
            let finalized = FinalizedCheckpoint {
                height: 0,
                hash: consensus.tip_hash,
            };
            let ctx = Self {
                store,
                state: consensus.state,
                recent_headers: consensus.headers,
                tip_height: consensus.tip_height,
                tip_hash: consensus.tip_hash,
                tip_chain_work,
                finalized,
                defer_finality_updates: false,
            };
            // Persist easy genesis.
            {
                use crate::consensus::da_prune::BlockUndoLog;
                let genesis = *ctx
                    .recent_headers
                    .get(&0)
                    .expect("easy genesis header must exist");
                let genesis_hash = block_id(&genesis);
                let meta = ConsensusMeta {
                    tip_height: 0,
                    tip_hash: genesis_hash,
                    cumulative_chainwork: tip_chain_work,
                    finalized,
                };
                ctx.store.commit_block(
                    &genesis,
                    &genesis_hash,
                    &BlockUndoLog::empty(0, genesis.log_slots),
                    &[],
                    &[],
                    &[],
                    None,
                    &meta,
                    false,
                )?;
            }
            Ok(ctx)
        } else {
            Self::restore_from_mdbx(store)
        }
    }

    fn persist_genesis(&self) -> Result<(), MdbxContextError> {
        use crate::consensus::da_prune::BlockUndoLog;
        use crate::consensus::genesis::genesis_header;

        let genesis = genesis_header();
        let genesis_hash = block_id(&genesis);
        let meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: genesis_hash,
            cumulative_chainwork: self.tip_chain_work,
            finalized: self.finalized,
        };

        // Write genesis header + tip + state_meta + consensus_meta in one transaction.
        // For genesis: segments are all virtual-zero, no dirty segments.
        self.store.commit_block(
            &genesis,
            &genesis_hash,
            &BlockUndoLog::empty(0, genesis.log_slots),
            &[], // no dirty segments (all virtual zero)
            &[],
            &[],
            None, // no block bytes for genesis
            &meta,
            false,
        )?;
        Ok(())
    }

    fn restore_from_mdbx(store: MdbxStore) -> Result<Self, MdbxContextError> {
        // 1. Read non-optional consensus metadata.
        let meta = store
            .get_consensus_meta()?
            .ok_or(MdbxContextError::Corrupt("missing consensus_meta"))?;
        let tip_height = meta.tip_height;
        let tip_hash = meta.tip_hash;
        let finalized = meta.finalized;

        if store.get_chain_tip()? != Some((tip_height, tip_hash)) {
            return Err(MdbxContextError::Corrupt(
                "chain_tip mismatch with consensus_meta",
            ));
        }
        if finalized.height > tip_height {
            return Err(MdbxContextError::Corrupt(
                "finalized checkpoint is above canonical tip",
            ));
        }
        let stored_tip_chain_work = store
            .get_chain_work(tip_height)?
            .ok_or(MdbxContextError::Corrupt("missing exact chainwork for tip"))?;
        if stored_tip_chain_work != meta.cumulative_chainwork {
            return Err(MdbxContextError::Corrupt(
                "tip chainwork mismatch with consensus_meta",
            ));
        }

        // 2. Read state_meta.
        let (log_slots, active_slot_count, alloc_counter) = store
            .get_state_meta()?
            .ok_or(MdbxContextError::Corrupt("missing state_meta"))?;
        // 3. Rebuild SegmentedFriState from stored segments.
        //    Use `set_segment_columns` (not `set_slot`) so that restored
        //    segments are NOT marked as MDBX-dirty — they are already in MDBX.
        let mut seg_state = SegmentedFriState::new_empty(log_slots as usize);
        let all_segs = store.all_segments()?;
        for (seg_id, _eff, cols) in all_segs {
            for ((&value, &owner_hi), &owner_lo) in cols
                .values
                .iter()
                .zip(cols.owners_hi.iter())
                .zip(cols.owners_lo.iter())
            {
                let slot = crate::fri_state::SlotValue {
                    value,
                    owner_hi,
                    owner_lo,
                };
                if !slot.is_empty() && slot.creation_id() > alloc_counter {
                    return Err(MdbxContextError::Corrupt(
                        "persisted slot creation_id exceeds alloc_counter",
                    ));
                }
            }
            seg_state.set_segment_columns(seg_id, cols);
        }
        // Confirm: after restore, mdbx_dirty must be empty.
        debug_assert_eq!(
            seg_state.dirty_segment_ids().count(),
            0,
            "set_segment_columns must not pollute mdbx_dirty"
        );

        // 3b. Integrity check: verify the reloaded state produces the correct
        //     state root.  This catches silent disk corruption or MDBX bit-rot
        //     in the segment columns before the node starts serving requests.
        let tip_hdr = store
            .get_header(tip_height)?
            .ok_or(MdbxContextError::Corrupt("tip header missing from store"))?;
        if block_id(&tip_hdr) != tip_hash {
            return Err(MdbxContextError::Corrupt(
                "tip hash mismatch with persisted tip header",
            ));
        }
        if log_slots != tip_hdr.log_slots
            || active_slot_count != tip_hdr.active_slot_count
            || alloc_counter != tip_hdr.alloc_counter
        {
            return Err(MdbxContextError::Corrupt(
                "state_meta counters mismatch with persisted tip header",
            ));
        }
        let finalized_hdr =
            store
                .get_header(finalized.height)?
                .ok_or(MdbxContextError::Corrupt(
                    "finalized header missing from store",
                ))?;
        if block_id(&finalized_hdr) != finalized.hash {
            return Err(MdbxContextError::Corrupt(
                "finalized hash mismatch with persisted finalized header",
            ));
        }
        // 4. Rebuild ChainState and the direct exact UTXO root.
        let mut state = ChainState::from_loaded_parts(seg_state, active_slot_count, alloc_counter)
            .map_err(|_| MdbxContextError::Corrupt("exact state root rebuild failed"))?;
        if state
            .try_state_root()
            .map_err(|_| MdbxContextError::Corrupt("exact state root rebuild failed"))?
            != tip_hdr.state_root
        {
            return Err(MdbxContextError::Corrupt(
                "state root mismatch after restore: segment data is corrupt",
            ));
        }

        // 5. Rebuild recent headers (last MEDIAN_TIME_BLOCKS + ANCHOR_DEPTH blocks).
        let window = (MEDIAN_TIME_BLOCKS as u64) + ANCHOR_DEPTH;
        let start_height = tip_height.saturating_sub(window);
        let mut recent_headers = HashMap::new();
        for h in start_height..=tip_height {
            if let Some(hdr) = store.get_header(h)? {
                recent_headers.insert(h, hdr);
            }
        }

        // 6. Use exact persisted cumulative chainwork.
        let tip_chain_work = meta.cumulative_chainwork;

        Ok(Self {
            store,
            state,
            recent_headers,
            tip_height,
            tip_hash,
            tip_chain_work,
            finalized,
            defer_finality_updates: false,
        })
    }

    // -----------------------------------------------------------------------
    // Block application
    // -----------------------------------------------------------------------

    fn finalized_for_tip(&self, tip_height: u64) -> Result<FinalizedCheckpoint, MdbxContextError> {
        let finalized_height = tip_height.saturating_sub(CONSENSUS_FINALITY_DEPTH);
        if finalized_height <= self.finalized.height {
            return Ok(self.finalized);
        }
        let header =
            self.get_header_from_store(finalized_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "missing header for finalized checkpoint",
                ))?;
        Ok(FinalizedCheckpoint {
            height: finalized_height,
            hash: block_id(&header),
        })
    }

    fn commit_applied_next_block(
        &mut self,
        block: &Block,
        undo: &crate::consensus::da_prune::BlockUndoLog,
        state_before_apply: &ChainState,
    ) -> Result<(), MdbxContextError> {
        let dirty_ids: Vec<u16> = self.state.state.dirty_segment_ids().collect();
        let eff_log = self.state.state.effective_log_segment_size() as u8;
        let dirty_segments: Vec<(u16, u8, _)> = dirty_ids
            .iter()
            .map(|&seg_id| {
                let cols = self.state.state.segment_columns_for_persistence(seg_id);
                (seg_id, eff_log, cols)
            })
            .collect();
        let dirty_refs: Vec<(u16, u8, &_)> = dirty_segments
            .iter()
            .map(|(id, eff, cols)| (*id, *eff, cols))
            .collect();

        let tx_hashes: Vec<TxBodyHash> =
            block.transactions.iter().map(|t| t.tx_body_hash).collect();
        let block_hash = block_id(&block.header);
        let new_tip_chain_work = add_work(
            &self.tip_chain_work,
            &block_work(&block.header.difficulty_target),
        );
        let new_finalized = if self.defer_finality_updates {
            self.finalized
        } else {
            self.finalized_for_tip(block.header.height)?
        };
        let consensus_meta = ConsensusMeta {
            tip_height: block.header.height,
            tip_hash: block_hash,
            cumulative_chainwork: new_tip_chain_work,
            finalized: new_finalized,
        };
        if let Err(e) = self.store.commit_block(
            &block.header,
            &block_hash,
            undo,
            &dirty_refs,
            &tx_hashes,
            &[],
            Some(&block.to_bytes()),
            &consensus_meta,
            false,
        ) {
            self.state = state_before_apply.clone();
            self.state.state.clear_dirty();
            return Err(e.into());
        }

        self.recent_headers
            .insert(block.header.height, block.header);
        self.tip_height = block.header.height;
        self.tip_hash = block_hash;
        self.tip_chain_work = new_tip_chain_work;
        self.finalized = new_finalized;
        self.state.state.clear_dirty();

        let window = (MEDIAN_TIME_BLOCKS as u64) + ANCHOR_DEPTH;
        if self.tip_height > window {
            self.recent_headers.remove(&(self.tip_height - window - 1));
        }

        Ok(())
    }

    /// Production block application: proof-native only.
    ///
    /// For user-transaction blocks, `validate_and_apply` must verify the full
    /// network `BlockProof` against the pre-block state and mutate `state` to the
    /// post-block state (the node passes `noid_block::accept_block`).
    /// The sequential interpreter is not a second production validity source.
    /// Coinbase-only blocks are the sole no-proof exception, but they still go
    /// through this same method: detached-proof presence checks, cheap consensus checks,
    /// `apply_state_delta`, then atomic commit.
    pub fn apply_next_block<F, E>(
        &mut self,
        block: &Block,
        block_proof_bytes: &[u8],
        block_auth_sidecar_bytes: &[u8],
        local_time: u64,
        validate_and_apply: F,
    ) -> Result<[u8; 32], MdbxContextError>
    where
        F: FnOnce(
            &Block,
            &[u8],
            &[u8],
            &BlockHeader,
            &[u64],
            &[u64],
            u64,
            &AnchorInfo,
            &SegmentedFriState,
            &mut ChainState,
        ) -> Result<[u8; 32], E>,
        E: std::fmt::Display,
    {
        let has_user_txs = block.transactions.iter().any(|tx| !tx.body.is_coinbase);
        if !has_user_txs {
            crate::block::validate_block_proof_binding(block, block_proof_bytes).map_err(|e| {
                MdbxContextError::Consensus(ConsensusError::ShapeMismatch(format!(
                    "coinbase-only proof binding invalid: {e}"
                )))
            })?;
            if !block_auth_sidecar_bytes.is_empty() {
                return Err(MdbxContextError::Consensus(ConsensusError::ShapeMismatch(
                    "coinbase-only block unexpectedly carried auth sidecar bytes".to_string(),
                )));
            }
        }

        let parent = *self.tip_header();
        let prev_timestamps = self.prev_timestamps();
        let prev_active_counts = self.prev_active_counts();
        let anchor = self.anchor_info();
        self.preload_segments_for_block(block)?;
        if !has_user_txs {
            // The native coinbase-only path recomputes the exact post-root.
            // Until it has an incremental exact-tree cache, every live segment
            // must be resident so an unrelated eviction cannot turn the cached
            // parent root into a false post-root acceptance.
            self.preload_all_evicted_segments()?;
        }
        let pre_state = self.state.state.clone();
        let state_before_validation = self.state.clone();
        let undo = build_undo_log(&self.state, block);

        let new_state_root = if has_user_txs {
            match validate_and_apply(
                block,
                block_proof_bytes,
                block_auth_sidecar_bytes,
                &parent,
                &prev_timestamps,
                &prev_active_counts,
                local_time,
                &anchor,
                &pre_state,
                &mut self.state,
            ) {
                Ok(root) => root,
                Err(e) => {
                    self.state = state_before_validation;
                    self.state.state.clear_dirty();
                    return Err(MdbxContextError::Consensus(ConsensusError::ShapeMismatch(
                        format!("proof-native validation failed: {e}"),
                    )));
                }
            }
        } else {
            validate_block_checks(
                block,
                &parent,
                &prev_timestamps,
                &prev_active_counts,
                local_time,
                &anchor,
            )?;
            apply_state_delta(&mut self.state, block)
                .map_err(|e| {
                    self.state = state_before_validation.clone();
                    self.state.state.clear_dirty();
                    MdbxContextError::Consensus(ConsensusError::ShapeMismatch(format!(
                        "coinbase-only proven-delta apply failed: {e:?}"
                    )))
                })?
                .new_state_root
        };

        self.commit_applied_next_block(block, &undo, &state_before_validation)?;
        Ok(new_state_root)
    }

    // -----------------------------------------------------------------------
    // Immutable checkpoint generation
    // -----------------------------------------------------------------------

    /// Generate and persist an immutable local checkpoint package for the
    /// current hard-finalized height.
    ///
    /// This is not an alternate block acceptance path. It records an already
    /// accepted finalized prefix and fails closed if any retained body/proof/
    /// sidecar data needed by the package is missing.
    pub fn generate_immutable_checkpoint(
        &mut self,
    ) -> Result<ImmutableCheckpointPackage, MdbxContextError> {
        self.generate_immutable_checkpoint_at(self.finalized.height)
    }

    pub fn generate_immutable_checkpoint_at(
        &mut self,
        height: u64,
    ) -> Result<ImmutableCheckpointPackage, MdbxContextError> {
        if height != self.finalized.height {
            return Err(MdbxContextError::Corrupt(
                "checkpoint generation requires the latest finalized height",
            ));
        }
        if height > self.tip_height {
            return Err(MdbxContextError::Corrupt(
                "checkpoint height is above canonical tip",
            ));
        }
        if self.tip_height.saturating_sub(height) > CONSENSUS_FINALITY_DEPTH {
            return Err(MdbxContextError::Corrupt(
                "checkpoint height is outside retained undo window",
            ));
        }

        let header = self
            .get_header_from_store(height)?
            .ok_or(MdbxContextError::Corrupt("checkpoint header missing"))?;
        let block_hash = block_id(&header);
        if block_hash != self.finalized.hash {
            return Err(MdbxContextError::Corrupt(
                "checkpoint finalized hash mismatch",
            ));
        }
        let cumulative_chainwork = self
            .store
            .get_chain_work(height)?
            .ok_or(MdbxContextError::Corrupt("checkpoint chainwork missing"))?;

        let checkpoint_state = self.reconstruct_state_at_height(height)?;
        let state_root = checkpoint_state.utxo_root;
        if state_root != header.state_root {
            return Err(MdbxContextError::Corrupt(
                "checkpoint reconstructed state_root mismatch",
            ));
        }
        if checkpoint_state.state.log_slots() as u32 != header.log_slots {
            return Err(MdbxContextError::Corrupt(
                "checkpoint reconstructed log_slots mismatch",
            ));
        }
        if checkpoint_state.active_slot_count != header.active_slot_count {
            return Err(MdbxContextError::Corrupt(
                "checkpoint reconstructed active_slot_count mismatch",
            ));
        }
        if checkpoint_state.alloc_counter != header.alloc_counter {
            return Err(MdbxContextError::Corrupt(
                "checkpoint reconstructed alloc_counter mismatch",
            ));
        }

        let (segments, segment_payload_root) =
            checkpoint_segments_and_root(checkpoint_state.clone());
        let (covered_from, covered_to, block_body_root, block_proof_root, block_auth_sidecar_root) =
            self.checkpoint_payload_roots(height)?;

        let manifest = ImmutableCheckpointManifest {
            height,
            block_hash,
            cumulative_chainwork,
            log_slots: header.log_slots,
            active_slot_count: header.active_slot_count,
            alloc_counter: header.alloc_counter,
            state_root,
            covered_from,
            covered_to,
            block_body_root,
            block_proof_root,
            block_auth_sidecar_root,
            segment_payload_root,
            segment_count: segments.len() as u32,
        };
        let package = ImmutableCheckpointPackage { manifest, segments };
        let coverage = CheckpointCoverage {
            checkpoint_id: package.checkpoint_id(),
            height,
            block_hash,
            covered_from,
            covered_to,
            history_proof_covered_to: None,
        };
        self.store
            .put_checkpoint_package_and_coverage(&package, &coverage)?;
        Ok(package)
    }

    fn reconstruct_state_at_height(&mut self, height: u64) -> Result<ChainState, MdbxContextError> {
        self.preload_all_evicted_segments()?;
        let mut checkpoint_state = self.state.clone();
        for h in (height + 1..=self.tip_height).rev() {
            let undo = self
                .store
                .get_undo_log(h)?
                .ok_or(MdbxContextError::Corrupt(
                    "checkpoint reconstruction undo log missing",
                ))?;
            revert_block(&mut checkpoint_state.state, &undo);
            checkpoint_state
                .state
                .shrink_to_log_slots(undo.log_slots_before as usize)
                .map_err(|_| MdbxContextError::Corrupt("checkpoint state shrink failed"))?;
            crate::consensus::reorg::revert_state_counters(&mut checkpoint_state, &undo);
            checkpoint_state
                .rebuild_exact_utxo_root_loaded()
                .map_err(|_| MdbxContextError::Corrupt("checkpoint exact root rebuild failed"))?;
            let parent_header = self
                .store
                .get_header(h - 1)?
                .ok_or(MdbxContextError::Corrupt(
                    "checkpoint parent header missing",
                ))?;
            if undo.log_slots_before != parent_header.log_slots
                || checkpoint_state.state.log_slots() as u32 != parent_header.log_slots
                || checkpoint_state.utxo_root != parent_header.state_root
                || checkpoint_state.active_slot_count != parent_header.active_slot_count
                || checkpoint_state.alloc_counter != parent_header.alloc_counter
            {
                return Err(MdbxContextError::Corrupt(
                    "checkpoint undo does not restore parent header state",
                ));
            }
        }
        checkpoint_state
            .rebuild_exact_utxo_root_loaded()
            .map_err(|_| MdbxContextError::Corrupt("checkpoint exact root rebuild failed"))?;
        Ok(checkpoint_state)
    }

    /// Reconstruct an already-finalized state snapshot from the current state
    /// and retained undo logs. This is used by snapshot serving to return state
    /// at the same finalized height covered by the history proof.
    pub fn reconstruct_state_snapshot_at(
        &mut self,
        height: u64,
    ) -> Result<ChainState, MdbxContextError> {
        if height > self.tip_height {
            return Err(MdbxContextError::Corrupt(
                "snapshot reconstruction height is above canonical tip",
            ));
        }
        if self.tip_height.saturating_sub(height) > CONSENSUS_FINALITY_DEPTH {
            return Err(MdbxContextError::Corrupt(
                "snapshot reconstruction height is outside retained undo window",
            ));
        }
        self.reconstruct_state_at_height(height)
    }

    fn checkpoint_payload_roots(
        &self,
        height: u64,
    ) -> Result<(u64, u64, [u8; 32], [u8; 32], [u8; 32]), MdbxContextError> {
        if height == 0 {
            return Ok((
                1,
                0,
                checkpoint_payload_root(
                    CHECKPOINT_BLOCK_BODY_ROOT_DOMAIN,
                    std::iter::empty::<(u64, Vec<u8>)>(),
                ),
                checkpoint_payload_root(
                    CHECKPOINT_BLOCK_PROOF_ROOT_DOMAIN,
                    std::iter::empty::<(u64, Vec<u8>)>(),
                ),
                checkpoint_payload_root(
                    CHECKPOINT_AUTH_SIDECAR_ROOT_DOMAIN,
                    std::iter::empty::<(u64, Vec<u8>)>(),
                ),
            ));
        }

        let mut body_leaves: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut proof_leaves: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut sidecar_leaves: Vec<(u64, Vec<u8>)> = Vec::new();

        for h in 1..=height {
            let body = self
                .store
                .get_recent_block(h)?
                .ok_or(MdbxContextError::Corrupt("checkpoint block body missing"))?;
            let block = Block::from_bytes(&body)
                .map_err(|_| MdbxContextError::Corrupt("checkpoint block body decode failed"))?;
            let header = self
                .get_header_from_store(h)?
                .ok_or(MdbxContextError::Corrupt(
                    "checkpoint payload header missing",
                ))?;
            if block.header != header || block.header.height != h {
                return Err(MdbxContextError::Corrupt(
                    "checkpoint block body/header mismatch",
                ));
            }

            let has_user_txs = block.transactions.iter().any(|tx| !tx.body.is_coinbase);
            let proof = self.store.get_block_proof(h)?;
            let sidecar = self.store.get_block_auth_sidecar(h)?;
            let proof_bytes = match (has_user_txs, proof) {
                (true, Some(bytes)) if !bytes.is_empty() => bytes,
                (true, _) => {
                    return Err(MdbxContextError::Corrupt(
                        "checkpoint user block proof missing",
                    ))
                }
                (false, Some(bytes)) if !bytes.is_empty() => {
                    return Err(MdbxContextError::Corrupt(
                        "checkpoint coinbase block has unexpected proof bytes",
                    ))
                }
                (false, _) => Vec::new(),
            };
            let sidecar_bytes = match (has_user_txs, sidecar) {
                (true, Some(bytes)) if !bytes.is_empty() => bytes,
                (true, _) => {
                    return Err(MdbxContextError::Corrupt(
                        "checkpoint user block auth sidecar missing",
                    ))
                }
                (false, Some(bytes)) if !bytes.is_empty() => {
                    return Err(MdbxContextError::Corrupt(
                        "checkpoint coinbase block has unexpected auth sidecar bytes",
                    ))
                }
                (false, _) => Vec::new(),
            };

            body_leaves.push((h, body));
            proof_leaves.push((h, proof_bytes));
            sidecar_leaves.push((h, sidecar_bytes));
        }

        Ok((
            1,
            height,
            checkpoint_payload_root(CHECKPOINT_BLOCK_BODY_ROOT_DOMAIN, body_leaves),
            checkpoint_payload_root(CHECKPOINT_BLOCK_PROOF_ROOT_DOMAIN, proof_leaves),
            checkpoint_payload_root(CHECKPOINT_AUTH_SIDECAR_ROOT_DOMAIN, sidecar_leaves),
        ))
    }

    // -----------------------------------------------------------------------
    // Chain reorganization (MDBX-backed)
    // -----------------------------------------------------------------------

    /// Find the height of a block with the given hash in our chain.
    ///
    /// Searches `recent_headers` first (fast RAM lookup), then falls back to
    /// the MDBX hash→height index. Returns `None` if the hash is not found
    /// within the last `CONSENSUS_FINALITY_DEPTH` blocks.
    pub fn find_ancestor_height(&self, hash: &[u8; 32]) -> Option<u64> {
        // Search recent_headers first (fast path in RAM).
        for (height, header) in &self.recent_headers {
            if &block_id(header) == hash {
                return Some(*height);
            }
        }

        // Fall back to MDBX hash→height index.
        let oldest = self.tip_height.saturating_sub(CONSENSUS_FINALITY_DEPTH);
        match self.store.get_header_by_hash(hash) {
            Ok(Some(header)) if header.height >= oldest => Some(header.height),
            _ => None,
        }
    }

    /// Apply a chain reorganization backed by MDBX undo logs.
    ///
    /// 1. Reverts our chain from tip back to `ancestor_height` using MDBX undo logs.
    /// 2. Persists the reverted state to MDBX atomically (crash-safe checkpoint).
    /// 3. Applies `new_blocks` on top of `ancestor_height` through the caller's
    ///    proof-native applier. The node passes a closure that calls this type's
    ///    single production `apply_next_block` method with the matching `BlockProof`
    ///    bytes and `noid_block::accept_block`.
    ///
    /// Returns the hashes of reclaimed transactions for mempool re-admission.
    ///
    /// Fails if the reorg would change the finalized prefix, if an undo log is
    /// missing, or if any fork block fails full proof-native validation/application.
    pub fn apply_reorg_mdbx_with_applier<F>(
        &mut self,
        ancestor_height: u64,
        new_blocks: &[Block],
        local_time: u64,
        mut apply_block: F,
    ) -> Result<crate::consensus::reorg::ReorgResult, MdbxContextError>
    where
        F: FnMut(&mut Self, &Block, u64) -> Result<(), MdbxContextError>,
    {
        use crate::consensus::reorg::{revert_state_counters, ReorgResult};

        // Re-validate inside write lock: ancestor_height must be <= our CURRENT tip.
        // The caller computed ancestor_height outside the lock — if another task applied
        // blocks (or completed a reorg) in the meantime, ancestor_height may now be
        // ABOVE our tip, which would make saturating_sub silently return 0 and
        // discard the reorg. Fail loudly instead.
        if ancestor_height > self.tip_height {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }
        let reorg_depth = self.tip_height - ancestor_height; // safe: guarded above

        if ancestor_height < self.finalized.height {
            tracing::warn!(
                ancestor_height,
                finalized_height = self.finalized.height,
                "reorg rejected: ancestor is below finalized checkpoint"
            );
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }
        if ancestor_height == self.finalized.height {
            let ancestor_header =
                self.get_header_from_store(ancestor_height)?
                    .ok_or(MdbxContextError::Corrupt(
                        "finalized ancestor header missing",
                    ))?;
            if block_id(&ancestor_header) != self.finalized.hash {
                tracing::warn!(
                    ancestor_height,
                    "reorg rejected: finalized checkpoint hash mismatch"
                );
                return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
            }
        }
        if reorg_depth > CONSENSUS_FINALITY_DEPTH {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }

        if reorg_depth == 0 {
            return Ok(ReorgResult {
                reverted_heights: vec![],
                applied_heights: vec![],
                reclaimed_tx_hashes: vec![],
            });
        }

        let state_before_reorg = self.state.clone();
        let recent_headers_before_reorg = self.recent_headers.clone();
        let tip_height_before_reorg = self.tip_height;
        let tip_hash_before_reorg = self.tip_hash;
        let tip_chain_work_before_reorg = self.tip_chain_work;

        #[allow(unused_assignments)]
        let mut reclaimed_tx_hashes: Vec<TxBodyHash> = Vec::new();
        #[allow(unused_assignments)]
        let mut reverted_heights: Vec<u64> = Vec::new();

        tracing::info!(
            "reorg: reverting height {}..{} depth={} new_blocks={}",
            self.tip_height,
            ancestor_height,
            reorg_depth,
            new_blocks.len()
        );

        // Load the ancestor metadata before installing any reverted RAM
        // candidate. Read/corruption errors must leave state and tip pointers
        // byte-for-byte on the old canonical chain.
        let ancestor_header =
            self.get_header_from_store(ancestor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "ancestor header missing from store",
                ))?;
        let ancestor_chain_work =
            self.store
                .get_chain_work(ancestor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "missing exact chainwork for reorg ancestor",
                ))?;

        // -----------------------------------------------------------------------
        // Validate ALL undo logs before modifying any state.
        //
        // This is critical for safety: if we start reverting and then discover a
        // missing undo log mid-loop, we leave the node in an inconsistent state:
        //   - Some headers removed from recent_headers
        //   - tip_height still pointing to the OLD tip (not in recent_headers)
        //   → tip_header().expect() PANICS across all RPC threads
        //
        // By validating upfront, we either succeed fully or fail before touching
        // any in-memory state.
        // -----------------------------------------------------------------------
        {
            if ancestor_height != 0 && self.store.get_undo_log(ancestor_height)?.is_none() {
                return Err(MdbxContextError::Corrupt("reorg ancestor undo log missing"));
            }
            let range = ancestor_height + 1..=self.tip_height;
            let total = self.tip_height.saturating_sub(ancestor_height) as usize;
            let mut loaded = Vec::with_capacity(total);
            for height in range.rev() {
                match self.store.get_undo_log(height) {
                    Ok(Some(u)) => loaded.push((height, u)),
                    Ok(None) => {
                        tracing::error!(
                            height,
                            tip = self.tip_height,
                            ancestor = ancestor_height,
                            "reorg: undo log missing — cannot safely revert"
                        );
                        return Err(MdbxContextError::Corrupt(
                            "undo log missing: reorg aborted before any state modification",
                        ));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            // All undo logs present — store them.
            // (We traverse in reverse above to fail-fast on missing entries, so
            // re-sort to descending order for the revert loop below.)
            loaded.sort_by_key(|(h, _)| std::cmp::Reverse(*h));

            // -----------------------------------------------------------------------
            // Revert blocks from tip to ancestor (RAM only).
            // Safe to execute: all undo logs validated.
            // -----------------------------------------------------------------------
            let mut reclaimed_tx_hashes_inner: Vec<TxBodyHash> = Vec::new();
            let mut reverted_heights_inner: Vec<u64> = Vec::new();

            self.preload_all_evicted_segments()?;
            let mut candidate_state = self.state.clone();
            let mut candidate_headers = self.recent_headers.clone();

            for (height, undo) in &loaded {
                reclaimed_tx_hashes_inner.extend_from_slice(&undo.tx_hashes);
                revert_block(&mut candidate_state.state, undo);
                candidate_state
                    .state
                    .shrink_to_log_slots(undo.log_slots_before as usize)
                    .map_err(|_| MdbxContextError::Corrupt("state shrink after reorg failed"))?;
                revert_state_counters(&mut candidate_state, undo);
                candidate_state
                    .rebuild_exact_utxo_root_loaded()
                    .map_err(|_| {
                        MdbxContextError::Corrupt("exact root rebuild after reorg failed")
                    })?;
                let parent_header = self
                    .store
                    .get_header(height - 1)?
                    .ok_or(MdbxContextError::Corrupt("reorg parent header missing"))?;
                if undo.log_slots_before != parent_header.log_slots
                    || candidate_state.state.log_slots() as u32 != parent_header.log_slots
                    || candidate_state.utxo_root != parent_header.state_root
                    || candidate_state.active_slot_count != parent_header.active_slot_count
                    || candidate_state.alloc_counter != parent_header.alloc_counter
                {
                    return Err(MdbxContextError::Corrupt(
                        "reorg undo does not restore parent header state",
                    ));
                }
                candidate_headers.remove(height);
                reverted_heights_inner.push(*height);
            }

            self.state = candidate_state;
            self.recent_headers = candidate_headers;

            // Move into outer scope variables.
            reclaimed_tx_hashes = reclaimed_tx_hashes_inner;
            reverted_heights = reverted_heights_inner;
        }

        // -----------------------------------------------------------------------
        // Update tip pointers to the ancestor.
        // -----------------------------------------------------------------------
        self.tip_height = ancestor_height;
        self.tip_hash = block_id(&ancestor_header);
        self.tip_chain_work = ancestor_chain_work;

        // -----------------------------------------------------------------------
        // Persist the reverted state to MDBX atomically.
        // dirty segments are written before new blocks so crash
        // recovery always sees a consistent ancestor checkpoint.
        //
        // MDBX commit is atomic. If it fails, restore the pre-reorg RAM snapshot
        // so local state and the still-old durable tip remain consistent.
        // -----------------------------------------------------------------------
        if let Err(e) = self.persist_reorg_checkpoint(&ancestor_header, &reclaimed_tx_hashes) {
            tracing::error!(
                ancestor_height,
                "persist_reorg_checkpoint failed — restored pre-reorg RAM state"
            );
            self.state = state_before_reorg;
            self.recent_headers = recent_headers_before_reorg;
            self.tip_height = tip_height_before_reorg;
            self.tip_hash = tip_hash_before_reorg;
            self.tip_chain_work = tip_chain_work_before_reorg;
            return Err(e);
        }

        // -----------------------------------------------------------------------
        // Apply fork blocks via the caller's proof-native applier.
        // -----------------------------------------------------------------------
        let mut applied_heights: Vec<u64> = Vec::new();
        let previous_defer_finality = self.defer_finality_updates;
        self.defer_finality_updates = true;

        for block in new_blocks {
            match apply_block(self, block, local_time) {
                Ok(()) => {
                    applied_heights.push(block.header.height);
                    tracing::info!(height = block.header.height, "reorg: applied new block");
                }
                Err(e) => {
                    self.defer_finality_updates = previous_defer_finality;
                    tracing::error!(height = block.header.height, err = ?e, "reorg: failed to apply block");
                    return Err(e);
                }
            }
        }

        self.defer_finality_updates = previous_defer_finality;
        let finalized_after_reorg = self.finalized_for_tip(self.tip_height)?;
        if finalized_after_reorg != self.finalized {
            let meta = ConsensusMeta {
                tip_height: self.tip_height,
                tip_hash: self.tip_hash,
                cumulative_chainwork: self.tip_chain_work,
                finalized: finalized_after_reorg,
            };
            self.store.put_consensus_meta(&meta)?;
            self.finalized = finalized_after_reorg;
        }

        tracing::info!(
            reverted = reverted_heights.len(),
            applied = applied_heights.len(),
            new_tip = self.tip_height,
            "reorg complete"
        );

        Ok(ReorgResult {
            reverted_heights,
            applied_heights,
            reclaimed_tx_hashes,
        })
    }

    /// Persist the reverted chain state to MDBX after the reorg revert phase.
    ///
    /// Writes all segments marked dirty by `revert_block`, updates `chain_tip`
    /// and `state_meta`, and preserves the existing undo log at `ancestor_height`
    /// — all in one atomic MDBX transaction.
    fn persist_reorg_checkpoint(
        &mut self,
        ancestor_header: &BlockHeader,
        reverted_tx_hashes: &[TxBodyHash],
    ) -> Result<(), MdbxContextError> {
        use crate::consensus::da_prune::BlockUndoLog;

        // Collect all segments dirtied by the revert_block calls.
        let dirty_ids: Vec<u16> = self.state.state.dirty_segment_ids().collect();
        let eff_log = self.state.state.effective_log_segment_size() as u8;
        let dirty_segments: Vec<(u16, u8, _)> = dirty_ids
            .iter()
            .map(|&seg_id| {
                let cols = self.state.state.segment_columns_for_persistence(seg_id);
                (seg_id, eff_log, cols)
            })
            .collect();
        let dirty_refs: Vec<(u16, u8, &_)> = dirty_segments
            .iter()
            .map(|(id, eff, cols)| (*id, *eff, cols))
            .collect();

        let ancestor_hash = block_id(ancestor_header);
        let consensus_meta = ConsensusMeta {
            tip_height: ancestor_header.height,
            tip_hash: ancestor_hash,
            cumulative_chainwork: self.tip_chain_work,
            finalized: self.finalized,
        };

        // Read the ancestor's existing undo log so we don't overwrite it with
        // empty — it must remain intact for any future reorg within finality.
        let existing_undo = match self.store.get_undo_log(ancestor_header.height)? {
            Some(undo) => undo,
            None if ancestor_header.height == 0 => {
                BlockUndoLog::empty(0, ancestor_header.log_slots)
            }
            None => {
                return Err(MdbxContextError::Corrupt("reorg ancestor undo log missing"));
            }
        };

        // Atomic commit: dirty segments + updated chain_tip + state_meta.
        // The ancestor's header and hash→height index are idempotently re-written.
        self.store
            .commit_block(
                ancestor_header,
                &ancestor_hash,
                &existing_undo,
                &dirty_refs,
                &[],
                reverted_tx_hashes,
                None, // no block bytes (stored earlier or DA-pruned)
                &consensus_meta,
                true,
            )
            .map_err(MdbxContextError::Store)?;

        // Clear dirty tracking so apply_next_block starts with a clean slate.
        self.state.state.clear_dirty();

        Ok(())
    }

    /// Preload ALL evicted segments back into RAM.
    ///
    /// Must be called before cloning the state for the block template builder.
    /// The template builder clones `ctx.state` to a scratch state; if any
    /// segments are evicted (None but with data in MDBX), `apply_delta` would
    /// materialise them as all-zeros, producing a wrong FRI root and a
    /// `BadStateRoot` consensus error.
    ///
    /// Cost: one MDBX read per evicted segment, O(evicted_count). Called once
    /// per block template refresh; negligible at mainnet (15 s blocks).
    pub fn preload_all_evicted_segments(&mut self) -> Result<(), MdbxContextError> {
        let evicted: Vec<u16> = self.state.state.evicted_segment_ids().collect();
        for seg_id in evicted {
            match self.store.get_segment(seg_id) {
                Ok(Some((_eff, cols))) => {
                    self.state.state.restore_evicted_segment(seg_id, cols);
                }
                Ok(None) => {
                    return Err(MdbxContextError::Corrupt(
                        "evicted live segment is missing from MDBX",
                    ));
                }
                Err(e) => return Err(MdbxContextError::Store(e)),
            }
        }
        Ok(())
    }

    /// Preload evicted segments that the block will access.
    ///
    /// Checks each input slot (must be non-empty = need to read existing data)
    /// and each output slot (must be empty = need to read to verify).
    /// Reloads from MDBX any segment that is currently evicted.
    pub fn preload_segments_for_block(&mut self, block: &Block) -> Result<(), MdbxContextError> {
        let eff_log = self.state.state.effective_log_segment_size();
        let mut needed: std::collections::HashSet<u16> = std::collections::HashSet::new();

        for tx in &block.transactions {
            for inp in tx.body.inputs.iter().filter(|i| i.valid) {
                needed.insert((inp.slot_index >> eff_log) as u16);
            }
            for out in tx.body.outputs.iter().filter(|o| o.valid) {
                needed.insert((out.slot_index >> eff_log) as u16);
            }
            // Coinbase slot (splitmix64 assigned): include all recently-checked
            // slots from the allocator hints by checking coinbase outputs too.
        }

        for seg_id in needed {
            if self.state.state.is_evicted(seg_id) {
                // Reload from MDBX.
                match self.store.get_segment(seg_id) {
                    Ok(Some((_eff_log, cols))) => {
                        self.state.state.restore_evicted_segment(seg_id, cols);
                    }
                    Ok(None) => {
                        return Err(MdbxContextError::Corrupt(
                            "evicted live segment is missing from MDBX",
                        ));
                    }
                    Err(e) => return Err(MdbxContextError::Store(e)),
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // State snapshot sync
    // -----------------------------------------------------------------------

    /// Apply a full state snapshot received from a peer during initial sync.
    ///
    /// The caller must already have validated and persisted the canonical header
    /// chain through `tip_height` and accepted the snapshot proof policy.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_state_snapshot<I>(
        &mut self,
        tip_height: u64,
        tip_hash: [u8; 32],
        log_slots: u32,
        active_slot_count: u64,
        alloc_counter: u64,
        segments: I,
        recent_headers_bytes: &[Vec<u8>],
    ) -> Result<(), MdbxContextError>
    where
        I: IntoIterator<Item = (u16, u8, crate::segmented_state::SegmentColumns, [u8; 32])>,
    {
        if tip_height <= self.tip_height {
            return Err(MdbxContextError::Corrupt(
                "snapshot tip is not ahead of local state",
            ));
        }

        let tip_header = self
            .store
            .get_header(tip_height)?
            .ok_or(MdbxContextError::Corrupt("snapshot tip header missing"))?;
        if block_id(&tip_header) != tip_hash {
            return Err(MdbxContextError::Corrupt(
                "snapshot tip hash does not match canonical header",
            ));
        }
        if tip_header.log_slots != log_slots
            || tip_header.active_slot_count != active_slot_count
            || tip_header.alloc_counter != alloc_counter
        {
            return Err(MdbxContextError::Corrupt(
                "snapshot manifest counters do not match canonical header",
            ));
        }

        let mut decoded_recent = Vec::with_capacity(recent_headers_bytes.len());
        for bytes in recent_headers_bytes {
            decoded_recent.push(
                BlockHeader::from_bytes(bytes).map_err(|_| {
                    MdbxContextError::Corrupt("snapshot recent header decode failed")
                })?,
            );
        }
        if decoded_recent.is_empty() {
            return Err(MdbxContextError::Corrupt(
                "snapshot recent header window is empty",
            ));
        }
        if decoded_recent.last().map(|h| h.height) != Some(tip_height) {
            return Err(MdbxContextError::Corrupt(
                "snapshot recent header window does not end at tip",
            ));
        }
        for pair in decoded_recent.windows(2) {
            if pair[1].height != pair[0].height + 1 {
                return Err(MdbxContextError::Corrupt(
                    "snapshot recent headers are not contiguous",
                ));
            }
            if pair[1].prev_block_hash != block_id(&pair[0]) {
                return Err(MdbxContextError::Corrupt(
                    "snapshot recent headers are not linked",
                ));
            }
        }
        for header in &decoded_recent {
            let stored = self
                .store
                .get_header(header.height)?
                .ok_or(MdbxContextError::Corrupt(
                    "snapshot recent header missing from canonical store",
                ))?;
            if block_id(&stored) != block_id(header) {
                return Err(MdbxContextError::Corrupt(
                    "snapshot recent header conflicts with canonical store",
                ));
            }
        }

        let owned_segments: Vec<_> = segments.into_iter().collect();
        let mut seg_state = SegmentedFriState::new_empty(log_slots as usize);
        let expected_eff_log = seg_state.effective_log_segment_size() as u8;
        let mut live_count = 0u64;
        let mut seen_segments = std::collections::HashSet::new();
        for (seg_id, eff_log, cols, expected_root) in &owned_segments {
            if !seen_segments.insert(*seg_id) {
                return Err(MdbxContextError::Corrupt(
                    "snapshot contains duplicate segment id",
                ));
            }
            if *eff_log != expected_eff_log {
                return Err(MdbxContextError::Corrupt(
                    "snapshot segment effective log mismatch",
                ));
            }
            if (*seg_id as usize) >= seg_state.num_segments() {
                return Err(MdbxContextError::Corrupt(
                    "snapshot segment id out of range",
                ));
            }
            let computed_root = crate::fri_state::compute_segment_root(
                *eff_log as usize,
                &cols.values,
                &cols.owners_hi,
                &cols.owners_lo,
            );
            if computed_root != *expected_root {
                return Err(MdbxContextError::Corrupt("snapshot segment root mismatch"));
            }
            for ((&value, &owner_hi), &owner_lo) in cols
                .values
                .iter()
                .zip(cols.owners_hi.iter())
                .zip(cols.owners_lo.iter())
            {
                let slot = crate::fri_state::SlotValue {
                    value,
                    owner_hi,
                    owner_lo,
                };
                if slot.is_empty() {
                    continue;
                }
                if slot.creation_id() > alloc_counter {
                    return Err(MdbxContextError::Corrupt(
                        "snapshot slot creation_id exceeds alloc_counter",
                    ));
                }
                live_count = live_count.checked_add(1).ok_or(MdbxContextError::Corrupt(
                    "snapshot active slot count overflow",
                ))?;
            }
            seg_state.set_segment_columns(*seg_id, cols.clone());
        }
        if live_count != active_slot_count {
            return Err(MdbxContextError::Corrupt(
                "snapshot active slot count mismatch",
            ));
        }

        let mut snapshot_state =
            ChainState::from_loaded_parts(seg_state, active_slot_count, alloc_counter)
                .map_err(|_| MdbxContextError::Corrupt("snapshot exact state rebuild failed"))?;
        if snapshot_state
            .try_state_root()
            .map_err(|_| MdbxContextError::Corrupt("snapshot exact state rebuild failed"))?
            != tip_header.state_root
        {
            return Err(MdbxContextError::Corrupt(
                "snapshot reconstructed state_root mismatch",
            ));
        }
        snapshot_state.state.clear_dirty();

        let cumulative_chainwork = self
            .store
            .get_chain_work(tip_height)?
            .ok_or(MdbxContextError::Corrupt("snapshot tip chainwork missing"))?;
        // Snapshot manifests are served at a proof-covered finalized boundary.
        // The retained suffix is replayed after snapshot application, so the
        // snapshot height itself is the local finalized checkpoint.
        let finalized_height = tip_height;
        let finalized_header =
            self.store
                .get_header(finalized_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "snapshot finalized header missing",
                ))?;
        let finalized = FinalizedCheckpoint {
            height: finalized_height,
            hash: block_id(&finalized_header),
        };
        let consensus_meta = ConsensusMeta {
            tip_height,
            tip_hash,
            cumulative_chainwork,
            finalized,
        };
        let segment_refs: Vec<_> = owned_segments
            .iter()
            .map(|(seg_id, eff_log, cols, _)| (*seg_id, *eff_log, cols))
            .collect();
        self.store.install_state_snapshot(
            &tip_header,
            &tip_hash,
            &consensus_meta,
            &segment_refs,
        )?;

        self.state = snapshot_state;
        self.recent_headers.clear();
        for header in decoded_recent {
            self.recent_headers.insert(header.height, header);
        }
        self.tip_height = tip_height;
        self.tip_hash = tip_hash;
        self.tip_chain_work = cumulative_chainwork;
        self.finalized = finalized;
        self.defer_finality_updates = false;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // ChainContext-compatible accessors
    // -----------------------------------------------------------------------

    pub fn tip_header(&self) -> &BlockHeader {
        self.recent_headers
            .get(&self.tip_height)
            .expect("tip header must always be in recent_headers")
    }

    pub fn header(&self, height: u64) -> Option<&BlockHeader> {
        self.recent_headers.get(&height)
    }

    /// Load any header from MDBX (including old ones not in RAM).
    pub fn get_header_from_store(&self, height: u64) -> Result<Option<BlockHeader>, StoreError> {
        // Check RAM first (fast path).
        if let Some(h) = self.recent_headers.get(&height) {
            return Ok(Some(*h));
        }
        self.store.get_header(height)
    }

    pub fn prev_timestamps(&self) -> Vec<u64> {
        let tip = self.tip_height;
        let start = tip.saturating_sub(MEDIAN_TIME_BLOCKS as u64 - 1);
        (start..=tip)
            .filter_map(|h| self.recent_headers.get(&h).map(|hdr| hdr.timestamp))
            .collect()
    }

    /// Collect the last `EXPANSION_WINDOW` `active_slot_count` values for the
    /// median expansion trigger. Always available: `recent_headers` covers
    /// `MEDIAN_TIME_BLOCKS + ANCHOR_DEPTH` (≥ EXPANSION_WINDOW) blocks.
    pub fn prev_active_counts(&self) -> Vec<u64> {
        let tip = self.tip_height;
        let start = tip.saturating_sub(EXPANSION_WINDOW.saturating_sub(1));
        (start..=tip)
            .filter_map(|h| self.recent_headers.get(&h).map(|hdr| hdr.active_slot_count))
            .collect()
    }

    pub fn anchor_info(&self) -> AnchorInfo {
        let anchor_height = epoch_anchor_height(self.tip_height);
        let anchor_header = self
            .recent_headers
            .get(&anchor_height)
            .unwrap_or_else(|| self.tip_header());
        AnchorInfo {
            anchor_height,
            anchor_timestamp: anchor_header.timestamp,
            anchor_target: anchor_header.difficulty_target,
        }
    }

    /// Check whether `anchor_hash` references a known header within the
    /// ANCHOR_DEPTH window relative to `tip_height`.
    ///
    /// Used by the template builder to filter out transactions whose
    /// epoch_anchor has expired since mempool admission.
    pub fn is_anchor_fresh(&self, anchor_hash: &[u8; 32], tip_height: u64) -> bool {
        let lo = tip_height.saturating_sub(ANCHOR_DEPTH);
        (lo..=tip_height).any(|h| {
            self.recent_headers
                .get(&h)
                .map(|hdr| block_id(hdr) == *anchor_hash)
                .unwrap_or(false)
        })
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }
    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }
    pub fn tip_chain_work(&self) -> &[u8; 32] {
        &self.tip_chain_work
    }
    pub fn finalized_checkpoint(&self) -> FinalizedCheckpoint {
        self.finalized
    }
}

fn checkpoint_segments_and_root(
    mut state: ChainState,
) -> (Vec<CheckpointSegmentPayload>, [u8; 32]) {
    let eff_log = state.state.effective_log_segment_size() as u8;
    let active_segments: Vec<u16> = state.state.active_segment_ids().collect();
    let mut segments = Vec::with_capacity(active_segments.len());

    for segment_id in active_segments {
        let cols = state.state.segment_columns_for_persistence(segment_id);
        let encoded_segment = encode_segment(&cols, eff_log);
        segments.push(CheckpointSegmentPayload {
            segment_id,
            effective_log_segment_size: eff_log,
            encoded_segment,
        });
    }

    let root = checkpoint_payload_root(
        CHECKPOINT_SEGMENT_PAYLOAD_ROOT_DOMAIN,
        segments
            .iter()
            .map(|segment| (segment.segment_id as u64, segment.encoded_segment.clone())),
    );
    (segments, root)
}

// The old `ApplySegmentColumns` extension trait has been removed.
// Segment restore now uses `SegmentedFriState::set_segment_columns` directly,
// which is faster (O(1) per segment vs O(n) slot-by-slot), correct about dirty
// tracking, and avoids triggering FRI NTT recomputation during restore.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{compute_tx_root, Block};
    use crate::block_header::BlockHeader;
    use crate::consensus::{params::BLOCK_TIME, pow::block_id};
    use noid_poseidon2b::primitives::Address;

    fn build_empty_block_on(ctx: &mut MdbxChainContext) -> Block {
        use crate::chain_context::TEST_TARGET;
        let parent = *ctx.tip_header();
        let new_root = ctx.state.state_root();

        // Use TEST_TARGET so nonce=0 trivially satisfies PoW.
        // ASERT with perfect BLOCK_TIME timing returns TEST_TARGET → consistent.
        let header = BlockHeader {
            prev_block_hash: block_id(&parent),
            state_root: new_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        Block {
            header,
            transactions: vec![],
        }
    }

    fn build_coinbase_block_on(
        ctx: &mut MdbxChainContext,
        slot_index: u32,
        owner_seed: u8,
    ) -> Block {
        use crate::chain_context::TEST_TARGET;
        use crate::consensus::emission::block_reward;
        use noid_tx::{hash_tx_body_for_shape, Transaction, TxBody, TxOutput, TxShape};

        let parent = *ctx.tip_header();
        let owner = Address([owner_seed; 32]);
        let body = TxBody::standard(
            block_id(&parent),
            0,
            vec![],
            vec![TxOutput {
                slot_index,
                value: block_reward(parent.log_slots),
                owner,
                valid: true,
            }],
            true,
        );
        let tx_body_hash = hash_tx_body_for_shape(
            TxShape::Standard4x8,
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        let tx = Transaction { body, tx_body_hash };

        let mut child = ctx.state.clone();
        crate::state::apply_tx(&mut child, &tx.body).expect("coinbase fixture applies");
        let header = BlockHeader {
            prev_block_hash: block_id(&parent),
            state_root: child.state_root(),
            tx_root: compute_tx_root(std::slice::from_ref(&tx)),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: owner,
            nonce: owner_seed as u128,
            difficulty_target: TEST_TARGET,
            log_slots: parent.log_slots,
            active_slot_count: child.active_slot_count,
            alloc_counter: child.alloc_counter,
        };
        Block {
            header,
            transactions: vec![tx],
        }
    }

    fn apply_coinbase_only_for_test(
        ctx: &mut MdbxChainContext,
        block: &Block,
        local_time: u64,
    ) -> Result<[u8; 32], MdbxContextError> {
        apply_coinbase_only_with_witness_for_test(ctx, block, &[], &[], local_time)
    }

    fn apply_coinbase_only_with_witness_for_test(
        ctx: &mut MdbxChainContext,
        block: &Block,
        block_proof_bytes: &[u8],
        block_auth_sidecar_bytes: &[u8],
        local_time: u64,
    ) -> Result<[u8; 32], MdbxContextError> {
        ctx.apply_next_block(
            block,
            block_proof_bytes,
            block_auth_sidecar_bytes,
            local_time,
            |_block,
             _proof_bytes,
             _auth_sidecar_bytes,
             _parent,
             _prev_timestamps,
             _prev_active_counts,
             _local_time,
             _anchor,
             _pre_state,
             _state|
             -> Result<[u8; 32], std::convert::Infallible> {
                unreachable!("empty/coinbase-only blocks do not call full proof validator")
            },
        )
    }

    #[test]
    fn open_fresh_database() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(ctx.tip_height(), 0);
        let h0 = *ctx.tip_header();
        let expected_anchor =
            crate::compute_header_chain_anchor(std::iter::once(&h0), *ctx.tip_chain_work())
                .expect("genesis anchor");
        assert_eq!(
            ctx.store.get_header_anchor(0).unwrap(),
            Some(expected_anchor)
        );
    }

    #[test]
    fn persist_reorg_checkpoint_rejects_missing_non_genesis_undo() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        let mut ancestor = *ctx.tip_header();
        ancestor.height = 1;

        assert!(matches!(
            ctx.persist_reorg_checkpoint(&ancestor, &[]),
            Err(MdbxContextError::Corrupt("reorg ancestor undo log missing"))
        ));
        assert!(ctx.store.get_undo_log(1).unwrap().is_none());
    }

    #[test]
    fn apply_one_block_and_reopen() {
        let dir = tempfile::tempdir().unwrap();

        // Apply one block.
        {
            let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            let block = build_empty_block_on(&mut ctx);
            let ts = block.header.timestamp + 1;
            apply_coinbase_only_for_test(&mut ctx, &block, ts).unwrap();
            assert_eq!(ctx.tip_height(), 1);
        }

        // Reopen and verify tip is persisted.
        {
            let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            assert_eq!(ctx.tip_height(), 1, "tip must survive restart");
            let h0 = ctx.store.get_header(0).unwrap().expect("h0");
            let h1 = ctx.store.get_header(1).unwrap().expect("h1");
            let expected_anchor =
                crate::compute_header_chain_anchor([h0, h1].iter(), *ctx.tip_chain_work())
                    .expect("h1 anchor");
            assert_eq!(
                ctx.store.get_header_anchor(1).unwrap(),
                Some(expected_anchor)
            );
        }
    }

    #[test]
    fn reorg_removes_orphan_tx_index_and_persists_new_branch_index() {
        let dir = tempfile::tempdir().unwrap();
        let competing_dir = tempfile::tempdir().unwrap();

        let (orphan_hash, canonical_hash) = {
            let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            let old_block = build_coinbase_block_on(&mut ctx, 7, 0x11);
            let orphan_hash = old_block.transactions[0].tx_body_hash;
            apply_coinbase_only_for_test(&mut ctx, &old_block, old_block.header.timestamp + 1)
                .unwrap();
            assert_eq!(
                ctx.store.get_tx_index(&orphan_hash.0).unwrap(),
                Some((1, 0))
            );

            // Build a genuinely competing height-1 block from the same easy
            // genesis in an independent context.
            let mut competing =
                MdbxChainContext::open_or_create_for_test(competing_dir.path()).unwrap();
            let new_block = build_coinbase_block_on(&mut competing, 9, 0x22);
            let canonical_hash = new_block.transactions[0].tx_body_hash;
            assert_ne!(orphan_hash, canonical_hash);

            let result = ctx
                .apply_reorg_mdbx_with_applier(
                    0,
                    std::slice::from_ref(&new_block),
                    new_block.header.timestamp + 1,
                    |ctx, block, local_time| {
                        apply_coinbase_only_for_test(ctx, block, local_time).map(|_| ())
                    },
                )
                .unwrap();
            assert_eq!(result.reverted_heights, vec![1]);
            assert_eq!(result.applied_heights, vec![1]);
            assert_eq!(
                ctx.store.get_tx_index(&orphan_hash.0).unwrap(),
                None,
                "an orphan transaction must not remain confirmed"
            );
            assert_eq!(
                ctx.store.get_tx_index(&canonical_hash.0).unwrap(),
                Some((1, 0))
            );

            (orphan_hash, canonical_hash)
        };

        let reopened = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(reopened.tip_height(), 1);
        assert_eq!(reopened.store.get_tx_index(&orphan_hash.0).unwrap(), None);
        assert_eq!(
            reopened.store.get_tx_index(&canonical_hash.0).unwrap(),
            Some((1, 0)),
            "canonical tx index must survive restart"
        );
    }

    #[test]
    fn expansion_upper_mint_reorg_restart_and_reexpand_stays_empty() {
        use crate::chain_context::TEST_TARGET;
        use crate::consensus::emission::block_reward;
        use crate::consensus::params::LOG_SEGMENT_SIZE;
        use noid_poseidon2b::primitives::SpendSecret;
        use noid_tx::{hash_tx_body_for_shape, Transaction, TxBody, TxInput, TxOutput, TxShape};

        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let parent_log = LOG_SEGMENT_SIZE;
        let mut state = ChainState::with_log_slots(parent_log as usize);
        // Structural persistence fixture: the occupancy counter is placed at
        // the expansion threshold without materialising 49k unrelated UTXOs.
        // The test exercises domain grow/undo/storage, not occupancy accounting.
        let expansion_trigger = (1u64 << parent_log) * 3 / 4;
        state.active_slot_count = expansion_trigger;
        let parent_root = state.cached_state_root();
        let parent = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: parent_root,
            tx_root: compute_tx_root(&[]),
            timestamp: 1_767_225_600,
            height: 0,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            log_slots: parent_log,
            active_slot_count: expansion_trigger,
            alloc_counter: 0,
        };
        let parent_hash = block_id(&parent);
        let tip_chain_work = block_work(&TEST_TARGET);
        let finalized = FinalizedCheckpoint {
            height: 0,
            hash: parent_hash,
        };
        let parent_meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: parent_hash,
            cumulative_chainwork: tip_chain_work,
            finalized,
        };
        store
            .commit_block(
                &parent,
                &parent_hash,
                &crate::consensus::da_prune::BlockUndoLog::empty(0, parent_log),
                &[],
                &[],
                &[],
                None,
                &parent_meta,
                false,
            )
            .unwrap();

        let mut recent_headers = HashMap::new();
        recent_headers.insert(0, parent);
        let mut ctx = MdbxChainContext {
            store,
            state,
            recent_headers,
            tip_height: 0,
            tip_hash: parent_hash,
            tip_chain_work,
            finalized,
            defer_finality_updates: false,
        };

        let child_log = parent_log + 1;
        let upper_slot = 1u32 << parent_log;
        let owner = Address([0x5A; 32]);
        let reward = block_reward(child_log);
        let body = TxBody::standard(
            parent_hash,
            0,
            vec![],
            vec![TxOutput {
                slot_index: upper_slot,
                value: reward,
                owner,
                valid: true,
            }],
            true,
        );
        let tx = Transaction {
            tx_body_hash: hash_tx_body_for_shape(
                TxShape::Standard4x8,
                &body.epoch_anchor,
                body.fee,
                &body.inputs,
                &body.outputs,
                body.is_coinbase,
            ),
            body,
        };
        let transient_owner = Address([0x6B; 32]);
        let transient_value = 17u64;
        let transient_mint_body = TxBody::standard(
            parent_hash,
            0,
            vec![],
            vec![TxOutput {
                slot_index: 7,
                value: transient_value,
                owner: transient_owner,
                valid: true,
            }],
            false,
        );
        let transient_mint = Transaction {
            tx_body_hash: hash_tx_body_for_shape(
                TxShape::Standard4x8,
                &transient_mint_body.epoch_anchor,
                transient_mint_body.fee,
                &transient_mint_body.inputs,
                &transient_mint_body.outputs,
                false,
            ),
            body: transient_mint_body,
        };
        let transient_spend_body = TxBody::standard(
            parent_hash,
            0,
            vec![TxInput {
                slot_index: 7,
                value: transient_value,
                creation_id: 2,
                owner: transient_owner,
                spend_secret: SpendSecret([0x7C; 32]),
                valid: true,
            }],
            vec![],
            false,
        );
        let transient_spend = Transaction {
            tx_body_hash: hash_tx_body_for_shape(
                TxShape::Standard4x8,
                &transient_spend_body.epoch_anchor,
                transient_spend_body.fee,
                &transient_spend_body.inputs,
                &transient_spend_body.outputs,
                false,
            ),
            body: transient_spend_body,
        };
        let minted = crate::fri_state::SlotValue::with_owner_fields(reward, 1, owner.as_fields());
        let mut child_state =
            ChainState::from_sparse_utxos(child_log as usize, &[(upper_slot, minted)], 2).unwrap();
        child_state.active_slot_count = expansion_trigger + 1;
        let child = Block {
            header: BlockHeader {
                prev_block_hash: parent_hash,
                state_root: child_state.cached_state_root(),
                tx_root: compute_tx_root(&[
                    tx.clone(),
                    transient_mint.clone(),
                    transient_spend.clone(),
                ]),
                timestamp: parent.timestamp + BLOCK_TIME,
                height: 1,
                miner_address: owner,
                nonce: 0,
                difficulty_target: TEST_TARGET,
                log_slots: child_log,
                active_slot_count: child_state.active_slot_count,
                alloc_counter: child_state.alloc_counter,
            },
            transactions: vec![tx, transient_mint, transient_spend],
        };

        let undo = build_undo_log(&ctx.state, &child);
        let state_before_child = ctx.state.clone();
        ctx.state = child_state;
        ctx.commit_applied_next_block(&child, &undo, &state_before_child)
            .unwrap();
        assert_eq!(ctx.state.state.log_slots(), child_log as usize);
        assert_eq!(ctx.state.state.slot(upper_slot).creation_id(), 1);
        assert_eq!(
            ctx.store.get_utxos_by_owner(&owner.0).unwrap(),
            vec![(upper_slot, reward)]
        );
        assert!(ctx
            .store
            .get_utxos_by_owner(&transient_owner.0)
            .unwrap()
            .is_empty());
        assert!(ctx.store.get_segment(1).unwrap().is_some());
        let stored_undo = ctx.store.get_undo_log(1).unwrap().unwrap();
        assert_eq!(stored_undo.log_slots_before, parent_log);
        assert!(stored_undo
            .slot_changes
            .contains(&(upper_slot, crate::fri_state::SlotValue::EMPTY)));
        assert!(stored_undo
            .slot_changes
            .contains(&(7, crate::fri_state::SlotValue::EMPTY)));

        ctx.apply_reorg_mdbx_with_applier(0, &[], child.header.timestamp + 1, |_, _, _| {
            Ok::<(), MdbxContextError>(())
        })
        .unwrap();
        assert_eq!(ctx.state.state.log_slots(), parent_log as usize);
        assert!(ctx.store.get_utxos_by_owner(&owner.0).unwrap().is_empty());
        assert!(ctx.store.get_segment(1).unwrap().is_none());
        drop(ctx);

        let mut reopened = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(reopened.tip_height(), 0);
        assert_eq!(reopened.state.state.log_slots(), parent_log as usize);
        assert!(reopened
            .store
            .all_segments()
            .unwrap()
            .iter()
            .all(|(segment_id, _, _)| *segment_id == 0));
        assert!(reopened
            .store
            .get_utxos_by_owner(&owner.0)
            .unwrap()
            .is_empty());
        assert!(reopened
            .store
            .get_utxos_by_owner(&transient_owner.0)
            .unwrap()
            .is_empty());
        assert!(reopened.store.get_segment(1).unwrap().is_none());
        reopened.state.expand_one();
        assert_eq!(
            reopened.state.state.slot(upper_slot),
            crate::fri_state::SlotValue::EMPTY
        );
        assert_eq!(
            reopened.state.try_state_root().unwrap(),
            crate::exact_state_hash::state_node_hash(
                parent_root,
                crate::exact_state_hash::zero_slot_roots(parent_log as usize)[parent_log as usize],
            )
        );
    }

    #[test]
    fn reopen_rejects_state_meta_counter_drift_from_tip_header() {
        let dir = tempfile::tempdir().unwrap();
        let tip = {
            let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            *ctx.tip_header()
        };
        {
            let store = MdbxStore::open(dir.path()).unwrap();
            store
                .overwrite_state_meta_for_test(
                    tip.log_slots,
                    tip.active_slot_count,
                    tip.alloc_counter + 1,
                )
                .unwrap();
        }

        assert!(matches!(
            MdbxChainContext::open_or_create_for_test(dir.path()),
            Err(MdbxContextError::Corrupt(
                "state_meta counters mismatch with persisted tip header"
            ))
        ));
    }

    #[test]
    fn reopen_rejects_persisted_creation_id_above_alloc_counter() {
        let dir = tempfile::tempdir().unwrap();
        {
            let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            let eff_log = ctx.state.state.effective_log_segment_size() as u8;
            let mut cols = crate::segmented_state::SegmentColumns::new_zero(1usize << eff_log);
            let owner = Address([0xA5; 32]);
            let slot = crate::fri_state::SlotValue::with_owner_fields(7, 1, owner.as_fields());
            cols.values[7] = slot.value;
            cols.owners_hi[7] = slot.owner_hi;
            cols.owners_lo[7] = slot.owner_lo;
            ctx.store
                .overwrite_segment_for_test(0, eff_log, &cols)
                .unwrap();
        }

        assert!(matches!(
            MdbxChainContext::open_or_create_for_test(dir.path()),
            Err(MdbxContextError::Corrupt(
                "persisted slot creation_id exceeds alloc_counter"
            ))
        ));
    }

    #[test]
    fn targeted_preload_rejects_missing_evicted_segment() {
        use noid_poseidon2b::primitives::TxBodyHash;
        use noid_tx::{Transaction, TxBody, TxOutput, TxShape};

        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        let owner = Address([0x3C; 32]);
        let eff_log = ctx.state.state.effective_log_segment_size();
        let mut cols = crate::segmented_state::SegmentColumns::new_zero(1usize << eff_log);
        let slot = crate::fri_state::SlotValue::with_owner_fields(5, 1, owner.as_fields());
        cols.values[7] = slot.value;
        cols.owners_hi[7] = slot.owner_hi;
        cols.owners_lo[7] = slot.owner_lo;
        let seg_id = 0;
        ctx.state.state.restore_evicted_segment(seg_id, cols);
        ctx.state.state.evict_segment(seg_id);
        assert!(ctx.state.state.is_evicted(seg_id));
        assert!(ctx.store.get_segment(seg_id).unwrap().is_none());

        let block = Block {
            header: *ctx.tip_header(),
            transactions: vec![Transaction {
                body: TxBody {
                    shape: TxShape::Standard4x8,
                    epoch_anchor: [0; 32],
                    fee: 0,
                    inputs: vec![],
                    outputs: vec![TxOutput {
                        slot_index: 7,
                        value: 1,
                        owner,
                        valid: true,
                    }],
                    is_coinbase: false,
                },
                tx_body_hash: TxBodyHash([0; 32]),
            }],
        };

        assert!(matches!(
            ctx.preload_segments_for_block(&block),
            Err(MdbxContextError::Corrupt(
                "evicted live segment is missing from MDBX"
            ))
        ));
    }

    #[test]
    fn invalid_detached_witness_does_not_poison_semantic_block() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        let initial_tip_hash = ctx.tip_hash();
        let block = build_empty_block_on(&mut ctx);
        let block_hash = block_id(&block.header);
        let ts = block.header.timestamp + 1;

        let invalid_proof = apply_coinbase_only_with_witness_for_test(
            &mut ctx,
            &block,
            b"invalid detached proof",
            &[],
            ts,
        );
        assert!(
            invalid_proof.is_err(),
            "coinbase-only block must reject unexpected proof bytes"
        );
        assert_eq!(ctx.tip_height(), 0);
        assert_eq!(ctx.tip_hash(), initial_tip_hash);
        assert_eq!(ctx.store.get_block_proof(1).unwrap(), None);
        assert_eq!(block_id(&block.header), block_hash);

        let invalid_sidecar = apply_coinbase_only_with_witness_for_test(
            &mut ctx,
            &block,
            &[],
            b"invalid auth sidecar",
            ts,
        );
        assert!(
            invalid_sidecar.is_err(),
            "coinbase-only block must reject unexpected auth sidecar bytes"
        );
        assert_eq!(ctx.tip_height(), 0);
        assert_eq!(ctx.tip_hash(), initial_tip_hash);

        let accepted = apply_coinbase_only_for_test(&mut ctx, &block, ts)
            .expect("same semantic block must accept with valid detached witness");
        assert_eq!(ctx.tip_height(), 1);
        assert_eq!(block_id(ctx.tip_header()), block_hash);
        assert_eq!(accepted, block.header.state_root);
    }

    #[test]
    fn three_blocks_survive_restart() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            for _ in 0..3 {
                let block = build_empty_block_on(&mut ctx);
                let ts = block.header.timestamp + 1;
                apply_coinbase_only_for_test(&mut ctx, &block, ts).unwrap();
            }
        }

        let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(ctx.tip_height(), 3);
        assert_eq!(ctx.state.active_slot_count, 0);
    }

    #[test]
    fn exact_chainwork_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let expected_work;

        {
            let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            for _ in 0..3 {
                let block = build_empty_block_on(&mut ctx);
                let ts = block.header.timestamp + 1;
                apply_coinbase_only_for_test(&mut ctx, &block, ts).unwrap();
            }
            expected_work = *ctx.tip_chain_work();
            assert_eq!(
                ctx.store.get_chain_work(ctx.tip_height()).unwrap(),
                Some(expected_work)
            );
        }

        let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(*ctx.tip_chain_work(), expected_work);
        assert_eq!(
            ctx.store.get_chain_work(ctx.tip_height()).unwrap(),
            Some(expected_work)
        );
    }

    #[test]
    fn finalized_pair_survives_restart() {
        use crate::consensus::params::CONSENSUS_FINALITY_DEPTH;

        let dir = tempfile::tempdir().unwrap();
        let expected_finalized;

        {
            let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            for _ in 0..(CONSENSUS_FINALITY_DEPTH + 2) {
                let block = build_empty_block_on(&mut ctx);
                let ts = block.header.timestamp + 1;
                apply_coinbase_only_for_test(&mut ctx, &block, ts).unwrap();
            }
            expected_finalized = ctx.finalized_checkpoint();
            assert_eq!(expected_finalized.height, 2);
        }

        let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(ctx.finalized_checkpoint(), expected_finalized);
        assert_eq!(
            ctx.store.get_consensus_meta().unwrap().unwrap().finalized,
            expected_finalized
        );
    }

    #[test]
    fn genesis_checkpoint_package_has_empty_payload_range() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        let package = ctx.generate_immutable_checkpoint().unwrap();

        assert_eq!(package.manifest.height, 0);
        assert_eq!(package.manifest.covered_from, 1);
        assert_eq!(package.manifest.covered_to, 0);
        assert_eq!(package.manifest.segment_count, 0);
        assert_eq!(
            package.manifest.block_body_root,
            checkpoint_payload_root(
                CHECKPOINT_BLOCK_BODY_ROOT_DOMAIN,
                std::iter::empty::<(u64, Vec<u8>)>(),
            )
        );
        assert_eq!(
            ctx.store.get_checkpoint_coverage().unwrap().unwrap().height,
            0
        );
    }

    #[test]
    fn immutable_checkpoint_package_persists_after_restart() {
        use crate::consensus::params::CONSENSUS_FINALITY_DEPTH;

        let dir = tempfile::tempdir().unwrap();
        let checkpoint_id;
        let checkpoint_height;

        {
            let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            for _ in 0..(CONSENSUS_FINALITY_DEPTH + 2) {
                let block = build_empty_block_on(&mut ctx);
                apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();
            }
            let package = ctx.generate_immutable_checkpoint().unwrap();
            checkpoint_id = package.checkpoint_id();
            checkpoint_height = package.manifest.height;

            assert_eq!(checkpoint_height, ctx.finalized_checkpoint().height);
            assert_eq!(package.manifest.covered_from, 1);
            assert_eq!(package.manifest.covered_to, checkpoint_height);
            assert_eq!(package.manifest.segment_count, 0);

            let coverage = ctx.store.get_checkpoint_coverage().unwrap().unwrap();
            assert_eq!(coverage.checkpoint_id, checkpoint_id);
            assert_eq!(coverage.height, checkpoint_height);
            assert_eq!(coverage.history_proof_covered_to, None);
        }

        {
            let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            let package = ctx
                .store
                .get_checkpoint_package(checkpoint_height)
                .unwrap()
                .expect("checkpoint package must survive restart");
            let coverage = ctx
                .store
                .get_checkpoint_coverage()
                .unwrap()
                .expect("checkpoint coverage must survive restart");
            assert_eq!(package.checkpoint_id(), checkpoint_id);
            assert_eq!(coverage.checkpoint_id, checkpoint_id);
        }
    }

    #[test]
    fn checkpoint_generation_rejects_non_latest_finalized_height() {
        use crate::consensus::params::CONSENSUS_FINALITY_DEPTH;

        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        for _ in 0..(CONSENSUS_FINALITY_DEPTH + 2) {
            let block = build_empty_block_on(&mut ctx);
            apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();
        }

        assert!(matches!(
            ctx.generate_immutable_checkpoint_at(1),
            Err(MdbxContextError::Corrupt(
                "checkpoint generation requires the latest finalized height"
            ))
        ));
    }

    #[test]
    fn block_payloads_remain_after_finality_without_checkpoint_coverage() {
        use crate::consensus::params::CONSENSUS_FINALITY_DEPTH;

        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();

        let first = build_empty_block_on(&mut ctx);
        apply_coinbase_only_for_test(&mut ctx, &first, first.header.timestamp + 1).unwrap();
        ctx.store.put_block_proof(1, b"proof-1").unwrap();
        ctx.store.put_block_auth_sidecar(1, b"sidecar-1").unwrap();

        for _ in 0..(CONSENSUS_FINALITY_DEPTH + 2) {
            let block = build_empty_block_on(&mut ctx);
            apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();
        }

        assert!(ctx.store.get_recent_block(1).unwrap().is_some());
        assert_eq!(
            ctx.store.get_block_proof(1).unwrap(),
            Some(b"proof-1".to_vec())
        );
        assert_eq!(
            ctx.store.get_block_auth_sidecar(1).unwrap(),
            Some(b"sidecar-1".to_vec())
        );
    }

    #[test]
    fn block_payloads_prune_after_checkpoint_history_coverage() {
        use crate::consensus::params::CONSENSUS_FINALITY_DEPTH;

        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();

        let first = build_empty_block_on(&mut ctx);
        apply_coinbase_only_for_test(&mut ctx, &first, first.header.timestamp + 1).unwrap();
        ctx.store.put_block_proof(1, b"proof-1").unwrap();
        ctx.store.put_block_auth_sidecar(1, b"sidecar-1").unwrap();
        ctx.store.put_history_claim(1, b"claim-1").unwrap();
        ctx.store
            .put_accepted_block_certificate(1, b"certificate-1")
            .unwrap();

        for _ in 0..CONSENSUS_FINALITY_DEPTH {
            let block = build_empty_block_on(&mut ctx);
            apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();
        }
        assert_eq!(ctx.tip_height(), CONSENSUS_FINALITY_DEPTH + 1);
        assert!(ctx.store.get_recent_block(1).unwrap().is_some());

        ctx.store
            .put_checkpoint_coverage(&crate::checkpoint::CheckpointCoverage {
                checkpoint_id: [0xA5; 32],
                height: 1,
                block_hash: crate::hash_block_header(&first.header),
                covered_from: 1,
                covered_to: 1,
                history_proof_covered_to: Some(1),
            })
            .unwrap();
        let block = build_empty_block_on(&mut ctx);
        apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();

        assert_eq!(ctx.store.get_recent_block(1).unwrap(), None);
        assert_eq!(ctx.store.get_block_proof(1).unwrap(), None);
        assert_eq!(ctx.store.get_block_auth_sidecar(1).unwrap(), None);
        assert_eq!(ctx.store.get_history_claim(1).unwrap(), None);

        assert!(ctx.store.get_header(1).unwrap().is_some());
        assert!(ctx.store.get_header_anchor(1).unwrap().is_some());
        assert_eq!(
            ctx.store.get_accepted_block_certificate(1).unwrap(),
            Some(b"certificate-1".to_vec())
        );
    }

    #[test]
    fn block_payloads_do_not_prune_without_history_proof_coverage() {
        use crate::consensus::params::CONSENSUS_FINALITY_DEPTH;

        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();

        let first = build_empty_block_on(&mut ctx);
        apply_coinbase_only_for_test(&mut ctx, &first, first.header.timestamp + 1).unwrap();
        ctx.store.put_block_proof(1, b"proof-1").unwrap();
        ctx.store.put_block_auth_sidecar(1, b"sidecar-1").unwrap();
        ctx.store.put_history_claim(1, b"claim-1").unwrap();
        ctx.store
            .put_accepted_block_certificate(1, b"certificate-1")
            .unwrap();

        for _ in 0..CONSENSUS_FINALITY_DEPTH {
            let block = build_empty_block_on(&mut ctx);
            apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();
        }
        ctx.store
            .put_checkpoint_coverage(&crate::checkpoint::CheckpointCoverage {
                checkpoint_id: [0xA5; 32],
                height: 1,
                block_hash: crate::hash_block_header(&first.header),
                covered_from: 1,
                covered_to: 1,
                history_proof_covered_to: None,
            })
            .unwrap();
        let block = build_empty_block_on(&mut ctx);
        apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();

        assert!(ctx.store.get_recent_block(1).unwrap().is_some());
        assert_eq!(
            ctx.store.get_block_proof(1).unwrap(),
            Some(b"proof-1".to_vec())
        );
        assert_eq!(
            ctx.store.get_block_auth_sidecar(1).unwrap(),
            Some(b"sidecar-1".to_vec())
        );
        assert_eq!(
            ctx.store.get_history_claim(1).unwrap(),
            Some(b"claim-1".to_vec())
        );
        assert_eq!(
            ctx.store.get_accepted_block_certificate(1).unwrap(),
            Some(b"certificate-1".to_vec())
        );
    }

    #[test]
    fn block_payloads_do_not_prune_without_certificate_record() {
        use crate::consensus::params::CONSENSUS_FINALITY_DEPTH;

        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();

        let first = build_empty_block_on(&mut ctx);
        apply_coinbase_only_for_test(&mut ctx, &first, first.header.timestamp + 1).unwrap();
        ctx.store.put_block_proof(1, b"proof-1").unwrap();
        ctx.store.put_block_auth_sidecar(1, b"sidecar-1").unwrap();
        ctx.store.put_history_claim(1, b"claim-1").unwrap();

        for _ in 0..CONSENSUS_FINALITY_DEPTH {
            let block = build_empty_block_on(&mut ctx);
            apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();
        }
        ctx.store
            .put_checkpoint_coverage(&crate::checkpoint::CheckpointCoverage {
                checkpoint_id: [0xA5; 32],
                height: 1,
                block_hash: crate::hash_block_header(&first.header),
                covered_from: 1,
                covered_to: 1,
                history_proof_covered_to: Some(1),
            })
            .unwrap();
        let block = build_empty_block_on(&mut ctx);
        apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();

        assert!(ctx.store.get_recent_block(1).unwrap().is_some());
        assert_eq!(
            ctx.store.get_block_proof(1).unwrap(),
            Some(b"proof-1".to_vec())
        );
        assert_eq!(
            ctx.store.get_block_auth_sidecar(1).unwrap(),
            Some(b"sidecar-1".to_vec())
        );
        assert_eq!(
            ctx.store.get_history_claim(1).unwrap(),
            Some(b"claim-1".to_vec())
        );
    }

    #[test]
    fn state_root_consistent_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let root_after_block;

        {
            let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            let block = build_empty_block_on(&mut ctx);
            let ts = block.header.timestamp + 1;
            root_after_block = apply_coinbase_only_for_test(&mut ctx, &block, ts).unwrap();
        }

        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(
            ctx.state.state_root(),
            root_after_block,
            "state root must be identical after restart"
        );
    }

    /// Verify that `dirty_segment_ids()` is empty after restart (segments are
    /// not needlessly re-written to MDBX on the very first block).
    #[test]
    fn no_spurious_dirty_segments_after_restart() {
        let dir = tempfile::tempdir().unwrap();

        // First run: apply one block.
        {
            let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            let block = build_empty_block_on(&mut ctx);
            apply_coinbase_only_for_test(&mut ctx, &block, block.header.timestamp + 1).unwrap();
        }

        // Second run: open and verify no dirty segments are queued.
        let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(
            ctx.state.state.dirty_segment_ids().count(),
            0,
            "no segments should be marked MDBX-dirty after a clean restart"
        );
    }
}
