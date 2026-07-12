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
//! | Recent headers | RAM (MTP/expansion window) | Header validation |

use std::collections::HashMap;
use std::path::Path;

use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::chain_context::ChainContext;
use crate::consensus::{
    da_prune::{build_undo_log, revert_block, BlockUndoLog},
    difficulty::{add_work, block_work},
    epoch_anchor::{tx_epoch_anchor_height_for_child, validate_block_epoch_anchors},
    header::asert_anchor_height,
    params::{
        BLOCK_MAX_DISTINCT_SEGMENTS, CONSENSUS_FINALITY_DEPTH, EXPANSION_WINDOW, GENESIS_TARGET,
        LOG_SEGMENT_SIZE, MEDIAN_TIME_BLOCKS, TX_EPOCH_BLOCKS,
    },
    pow::block_id,
    validation::{validate_block_checks, AnchorInfo},
    ConsensusError,
};
use crate::segmented_state::SegmentedFriState;
use crate::state::{ChainState, StreamingSparseRoot};
use crate::storage::mdbx_store::StagedAcceptedBlockCommit;
#[cfg(test)]
use crate::storage::serial::encode_segment;
use crate::storage::{
    AcceptedBlockCommitData, ConsensusMeta, FinalizedCheckpoint, FinalizedSnapshotStaging,
    MdbxStore, StoreError,
};
use noid_poseidon2b::primitives::TxBodyHash;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum MdbxContextError {
    Store(StoreError),
    Consensus(ConsensusError),
    Corrupt(&'static str),
    ResourceLimit {
        resource: &'static str,
        actual: usize,
        maximum: usize,
    },
}

impl std::fmt::Display for MdbxContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Consensus(e) => write!(f, "consensus: {e}"),
            Self::Corrupt(msg) => write!(f, "corrupt: {msg}"),
            Self::ResourceLimit {
                resource,
                actual,
                maximum,
            } => write!(f, "resource limit: {resource} {actual} exceeds {maximum}"),
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

/// Output of the single proof-native acceptance call that is persisted with
/// the resulting state transition.
///
/// `history_claim_bytes` and `accepted_block_certificate_bytes` are opaque to
/// `noid_chain`, but mandatory at this boundary so a successful block commit
/// cannot leave the O(1)-history worker without its accepted inputs.
#[derive(Debug)]
pub struct AppliedBlockValidation {
    pub state_root: [u8; 32],
    pub history_claim_bytes: Vec<u8>,
    pub accepted_block_certificate_bytes: Vec<u8>,
}

impl AppliedBlockValidation {
    pub fn new(
        state_root: [u8; 32],
        history_claim_bytes: Vec<u8>,
        accepted_block_certificate_bytes: Vec<u8>,
    ) -> Self {
        Self {
            state_root,
            history_claim_bytes,
            accepted_block_certificate_bytes,
        }
    }
}

/// Borrowed large payloads for one candidate reorg block.
///
/// The reorg validator and final MDBX transaction both read these slices from
/// the caller's existing candidate buffer.  Staging never clones a block,
/// proof, or authorization sidecar into node RAM.
#[derive(Debug, Clone, Copy)]
pub struct ReorgBlockPayload<'a> {
    pub block: &'a Block,
    pub block_proof_bytes: &'a [u8],
    pub block_auth_sidecar_bytes: &'a [u8],
}

/// A shallow in-RAM reorg may retain the union of old-branch and replacement
/// segments until the single atomic commit. One maximally dispersed old block
/// plus one replacement block is supported; larger unions use snapshot sync.
const MAX_REORG_RESIDENT_SEGMENTS: usize = BLOCK_MAX_DISTINCT_SEGMENTS * 2;

fn track_reorg_segment(
    segment_ids: &mut std::collections::HashSet<u16>,
    slot_index: u32,
) -> Result<(), MdbxContextError> {
    segment_ids.insert((slot_index >> LOG_SEGMENT_SIZE) as u16);
    if segment_ids.len() > MAX_REORG_RESIDENT_SEGMENTS {
        return Err(MdbxContextError::ResourceLimit {
            resource: "reorg resident segments",
            actual: segment_ids.len(),
            maximum: MAX_REORG_RESIDENT_SEGMENTS,
        });
    }
    Ok(())
}

impl<'a> ReorgBlockPayload<'a> {
    pub fn new(
        block: &'a Block,
        block_proof_bytes: &'a [u8],
        block_auth_sidecar_bytes: &'a [u8],
    ) -> Self {
        Self {
            block,
            block_proof_bytes,
            block_auth_sidecar_bytes,
        }
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

    /// Recent headers needed for MTP, ASERT and the expansion median.
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

    /// Owned commits produced while a replacement branch is validated in RAM.
    /// `Some` suppresses per-block MDBX writes; the complete vector is installed
    /// together only after every replacement block succeeds.
    reorg_staging: Option<Vec<StagedAcceptedBlockCommit>>,
}

impl MdbxChainContext {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    fn load_streamed_chain_state(
        store: &MdbxStore,
        log_slots: u32,
        active_slot_count: u64,
        alloc_counter: u64,
        expected_root: [u8; 32],
    ) -> Result<ChainState, MdbxContextError> {
        let mut segmented = SegmentedFriState::new_empty(log_slots as usize);
        let effective_log = segmented.effective_log_segment_size();
        let expected_segment_len = 1usize << effective_log;
        let mut exact = StreamingSparseRoot::new(log_slots)
            .map_err(|_| MdbxContextError::Corrupt("invalid durable state depth"))?;
        let mut exact_segment_roots = Vec::new();
        let mut counted_live = 0u64;
        store.visit_segments(|segment_id, stored_log, columns| {
            if usize::from(stored_log) != effective_log
                || columns.values.len() != expected_segment_len
                || columns.owners_hi.len() != expected_segment_len
                || columns.owners_lo.len() != expected_segment_len
            {
                return Err(StoreError::Decode("invalid durable segment shape"));
            }
            let mut segment_live = 0u32;
            let base = (segment_id as u32) << effective_log;
            for local in 0..expected_segment_len {
                let slot = crate::fri_state::SlotValue {
                    value: columns.values[local],
                    owner_hi: columns.owners_hi[local],
                    owner_lo: columns.owners_lo[local],
                };
                if slot.is_empty() {
                    continue;
                }
                if slot.creation_id() > alloc_counter {
                    return Err(StoreError::Decode(
                        "persisted slot creation_id exceeds alloc_counter",
                    ));
                }
                segment_live = segment_live
                    .checked_add(1)
                    .ok_or(StoreError::Decode("durable segment live-count overflow"))?;
                exact
                    .push_leaf(
                        base | local as u32,
                        crate::exact_state_hash::slot_leaf_hash(slot),
                    )
                    .map_err(|_| StoreError::Decode("durable exact leaf is out of range"))?;
            }
            counted_live = counted_live
                .checked_add(u64::from(segment_live))
                .ok_or(StoreError::Decode("durable active count overflow"))?;
            let segment_root = crate::fri_state::compute_segment_root(
                effective_log,
                &columns.values,
                &columns.owners_hi,
                &columns.owners_lo,
            );
            segmented
                .install_evicted_segment_summary(segment_id, segment_live, segment_root)
                .map_err(StoreError::Decode)?;
            exact_segment_roots.push((
                segment_id,
                crate::state::exact_segment_root_from_columns(effective_log, &columns),
            ));
            Ok(())
        })?;
        if counted_live != active_slot_count {
            return Err(MdbxContextError::Corrupt(
                "durable active count does not match exact segments",
            ));
        }
        segmented.finish_evicted_segment_summaries();
        let root = exact
            .finish()
            .map_err(|_| MdbxContextError::Corrupt("durable exact root build failed"))?;
        if root != expected_root {
            return Err(MdbxContextError::Corrupt(
                "durable exact state root mismatch",
            ));
        }
        ChainState::from_evicted_parts(
            segmented,
            active_slot_count,
            alloc_counter,
            root,
            &exact_segment_roots,
        )
        .map_err(|_| MdbxContextError::Corrupt("durable exact segment summary mismatch"))
    }

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
                reorg_staging: None,
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
                        reorg_staging: None,
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
                reorg_staging: None,
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
            None,
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
        // 3. Validate the canonical metadata before streaming state columns.
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
        // 4. Verify the exact root and per-segment FRI roots while decoding
        //    one durable segment at a time.  The returned hot state retains
        //    only summaries; columns are faulted in lazily on first access.
        let state = Self::load_streamed_chain_state(
            &store,
            log_slots,
            active_slot_count,
            alloc_counter,
            tip_hdr.state_root,
        )?;

        // 5. Rebuild the bounded header window used by native header checks.
        let window = (MEDIAN_TIME_BLOCKS as u64).max(EXPANSION_WINDOW);
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
            reorg_staging: None,
        })
    }

    /// Reload the durable canonical tip without retaining a second full state
    /// image in RAM.  Used only to abort a staged reorg; MDBX is still on the
    /// old branch until the final atomic replacement transaction commits.
    fn reload_hot_state_from_mdbx(&mut self) -> Result<(), MdbxContextError> {
        let meta = self
            .store
            .get_consensus_meta()?
            .ok_or(MdbxContextError::Corrupt("missing consensus_meta"))?;
        let (log_slots, active_slot_count, alloc_counter) = self
            .store
            .get_state_meta()?
            .ok_or(MdbxContextError::Corrupt("missing state_meta"))?;
        let tip_header = self
            .store
            .get_header(meta.tip_height)?
            .ok_or(MdbxContextError::Corrupt("durable tip header missing"))?;
        if block_id(&tip_header) != meta.tip_hash
            || tip_header.log_slots != log_slots
            || tip_header.active_slot_count != active_slot_count
            || tip_header.alloc_counter != alloc_counter
        {
            return Err(MdbxContextError::Corrupt(
                "durable reorg recovery metadata mismatch",
            ));
        }

        // Release the failed candidate before decoding durable segments.  The
        // replacement is a sparse virtual-zero state and does not allocate the
        // full slot domain.
        self.state = ChainState::with_log_slots(log_slots as usize);
        self.recent_headers.clear();
        let state = Self::load_streamed_chain_state(
            &self.store,
            log_slots,
            active_slot_count,
            alloc_counter,
            tip_header.state_root,
        )?;

        let window = (MEDIAN_TIME_BLOCKS as u64).max(EXPANSION_WINDOW);
        let start_height = meta.tip_height.saturating_sub(window);
        let mut recent_headers = HashMap::new();
        for height in start_height..=meta.tip_height {
            if let Some(header) = self.store.get_header(height)? {
                recent_headers.insert(height, header);
            }
        }
        if !recent_headers.contains_key(&meta.tip_height) {
            return Err(MdbxContextError::Corrupt(
                "durable recent header window misses tip",
            ));
        }

        self.state = state;
        self.recent_headers = recent_headers;
        self.tip_height = meta.tip_height;
        self.tip_hash = meta.tip_hash;
        self.tip_chain_work = meta.cumulative_chainwork;
        self.finalized = meta.finalized;
        self.defer_finality_updates = false;
        self.reorg_staging = None;
        Ok(())
    }

    fn abort_staged_reorg(&mut self, original: MdbxContextError) -> MdbxContextError {
        self.reorg_staging = None;
        match self.reload_hot_state_from_mdbx() {
            Ok(()) => original,
            Err(reload) => reload,
        }
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

    /// Restore an uncommitted in-place transition from its bounded touched-set
    /// undo.  The durable store still points to `parent`, so retaining another
    /// full `ChainState` image solely for error handling is unnecessary.
    fn rollback_uncommitted_block(
        &mut self,
        undo: &crate::consensus::da_prune::BlockUndoLog,
        parent: &BlockHeader,
    ) -> Result<(), MdbxContextError> {
        self.state
            .state
            .apply_delta_unrooted(&undo.slot_changes)
            .map_err(|_| MdbxContextError::Corrupt("uncommitted block undo is out of range"))?;
        self.state
            .state
            .shrink_to_log_slots(undo.log_slots_before as usize)
            .map_err(|_| MdbxContextError::Corrupt("uncommitted block depth rollback failed"))?;
        self.state.active_slot_count = undo.active_slot_count_before;
        self.state.alloc_counter = undo.alloc_counter_before;
        self.state.utxo_root = parent.state_root;
        if self.state.state.log_slots() as u32 != parent.log_slots
            || self.state.active_slot_count != parent.active_slot_count
            || self.state.alloc_counter != parent.alloc_counter
        {
            return Err(MdbxContextError::Corrupt(
                "uncommitted block undo does not restore parent boundary",
            ));
        }
        self.state.state.clear_dirty();
        Ok(())
    }

    fn commit_applied_next_block(
        &mut self,
        block: &Block,
        block_proof_bytes: &[u8],
        block_auth_sidecar_bytes: &[u8],
        validation: &AppliedBlockValidation,
        undo: &crate::consensus::da_prune::BlockUndoLog,
        parent: &BlockHeader,
    ) -> Result<(), MdbxContextError> {
        let tx_hashes: Vec<TxBodyHash> = block.transactions.iter().map(|tx| tx.txid()).collect();
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
        let staged = self.reorg_staging.is_some();
        if let Some(replacement) = self.reorg_staging.as_mut() {
            replacement.push(StagedAcceptedBlockCommit {
                header: block.header,
                hash: block_hash,
                cumulative_chainwork: new_tip_chain_work,
                undo_log: undo.clone(),
                history_claim_bytes: validation.history_claim_bytes.clone(),
                accepted_block_certificate_bytes: validation
                    .accepted_block_certificate_bytes
                    .clone(),
            });
        } else {
            let consensus_meta = ConsensusMeta {
                tip_height: block.header.height,
                tip_hash: block_hash,
                cumulative_chainwork: new_tip_chain_work,
                finalized: new_finalized,
            };
            let commit_result = (|| -> Result<(), StoreError> {
                let dirty_ids: Vec<u16> = self.state.state.dirty_segment_ids().collect();
                let eff_log = self.state.state.effective_log_segment_size() as u8;
                let mut dirty_refs = Vec::with_capacity(dirty_ids.len());
                for segment_id in dirty_ids {
                    let columns =
                        if self.state.state.segment_live_count(segment_id) == 0 {
                            None
                        } else {
                            Some(self.state.state.try_get_segment_columns(segment_id).ok_or(
                                StoreError::Decode("dirty accepted segment is not resident"),
                            )?)
                        };
                    dirty_refs.push((segment_id, eff_log, columns));
                }
                self.store.commit_block(
                    &block.header,
                    &block_hash,
                    undo,
                    &dirty_refs,
                    &tx_hashes,
                    &[],
                    Some(&block.to_bytes()),
                    Some(AcceptedBlockCommitData {
                        block_proof_bytes,
                        block_auth_sidecar_bytes,
                        history_claim_bytes: &validation.history_claim_bytes,
                        accepted_block_certificate_bytes: &validation
                            .accepted_block_certificate_bytes,
                    }),
                    &consensus_meta,
                    false,
                )
            })();
            if let Err(e) = commit_result {
                let commit_error = MdbxContextError::from(e);
                return match self.rollback_uncommitted_block(undo, parent) {
                    Ok(()) => Err(commit_error),
                    Err(rollback_error) => Err(rollback_error),
                };
            }
        }

        self.recent_headers
            .insert(block.header.height, block.header);
        self.tip_height = block.header.height;
        self.tip_hash = block_hash;
        self.tip_chain_work = new_tip_chain_work;
        self.finalized = new_finalized;
        if !staged {
            self.state.state.clear_dirty();
            // The exact hierarchy is compact and current. Raw columns have
            // reached MDBX atomically, so retain no full segment merely because
            // it was touched by the latest block.
            self.state.state.evict_all_persisted_segments();
        }

        let window = (MEDIAN_TIME_BLOCKS as u64).max(EXPANSION_WINDOW);
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
    /// through the supplied proof-native validator so mint-slot emptiness and
    /// the exact transition are established before the atomic commit.
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
            &[u8; 32],
            &AnchorInfo,
            &mut ChainState,
        ) -> Result<AppliedBlockValidation, E>,
        E: std::fmt::Display,
    {
        let parent = *self.tip_header();
        let prev_timestamps = self.prev_timestamps();
        let prev_active_counts = self.prev_active_counts();
        let anchor = self.anchor_info();
        let tx_anchor_height = tx_epoch_anchor_height_for_child(block.header.height);
        let tx_anchor_header =
            self.get_header_from_store(tx_anchor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "canonical transaction epoch-anchor header missing",
                ))?;
        let tx_epoch_anchor_id = block_id(&tx_anchor_header);
        validate_block_epoch_anchors(block, tx_epoch_anchor_id, block_id(&parent))?;
        // All deterministic cheap checks, including bitmap-live resources
        // and the segment cap, precede proof decode, segment hydration, state
        // cloning, and undo allocation.
        validate_block_checks(
            block,
            &parent,
            &prev_timestamps,
            &prev_active_counts,
            local_time,
            &anchor,
        )?;

        let has_user_txs = block.transactions.iter().any(|tx| !tx.body.is_coinbase);
        if has_user_txs {
            use crate::consensus::wire_limits::{
                proof_sidecar_combined_len_ok, MAX_BLOCK_AUTH_SIDECAR_BYTES, MAX_BLOCK_PROOF_BYTES,
            };
            if block_proof_bytes.is_empty() || block_auth_sidecar_bytes.is_empty() {
                return Err(MdbxContextError::Consensus(ConsensusError::MissingProof));
            }
            if block_proof_bytes.len() > MAX_BLOCK_PROOF_BYTES
                || block_auth_sidecar_bytes.len() > MAX_BLOCK_AUTH_SIDECAR_BYTES
                || !proof_sidecar_combined_len_ok(
                    block_proof_bytes.len(),
                    block_auth_sidecar_bytes.len(),
                )
            {
                return Err(MdbxContextError::Consensus(ConsensusError::ShapeMismatch(
                    "block proof/auth sidecar exceeds wire limits".to_string(),
                )));
            }
        } else {
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

        self.preload_segments_for_preflighted_block(block)?;
        let undo = build_undo_log(&self.state, block);

        let validation = match validate_and_apply(
            block,
            block_proof_bytes,
            block_auth_sidecar_bytes,
            &parent,
            &prev_timestamps,
            &prev_active_counts,
            local_time,
            &tx_epoch_anchor_id,
            &anchor,
            &mut self.state,
        ) {
            Ok(validation) => validation,
            Err(e) => {
                self.rollback_uncommitted_block(&undo, &parent)?;
                return Err(MdbxContextError::Consensus(ConsensusError::ShapeMismatch(
                    format!("proof-native validation failed: {e}"),
                )));
            }
        };

        if validation.state_root != block.header.state_root {
            self.rollback_uncommitted_block(&undo, &parent)?;
            return Err(MdbxContextError::Consensus(ConsensusError::BadStateRoot));
        }
        if validation.history_claim_bytes.is_empty()
            || validation.accepted_block_certificate_bytes.is_empty()
        {
            self.rollback_uncommitted_block(&undo, &parent)?;
            return Err(MdbxContextError::Consensus(ConsensusError::ShapeMismatch(
                "proof-native acceptance returned incomplete durable artifacts".to_string(),
            )));
        }

        self.commit_applied_next_block(
            block,
            block_proof_bytes,
            block_auth_sidecar_bytes,
            &validation,
            &undo,
            &parent,
        )?;
        Ok(validation.state_root)
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
        replacement: &[ReorgBlockPayload<'_>],
        local_time: u64,
        mut apply_block: F,
    ) -> Result<crate::consensus::reorg::ReorgResult, MdbxContextError>
    where
        F: FnMut(&mut Self, &ReorgBlockPayload<'_>, u64) -> Result<(), MdbxContextError>,
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

        if self.reorg_staging.is_some() {
            return Err(MdbxContextError::Corrupt("nested reorg staging"));
        }

        tracing::info!(
            "reorg: reverting height {}..{} depth={} new_blocks={}",
            self.tip_height,
            ancestor_height,
            reorg_depth,
            replacement.len()
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
        let mut reorg_segment_ids = std::collections::HashSet::new();
        for payload in replacement {
            for tx in &payload.block.transactions {
                for (_, input) in tx.body.live_inputs() {
                    track_reorg_segment(&mut reorg_segment_ids, input.slot_index)?;
                }
                for (_, output) in tx.body.live_outputs() {
                    track_reorg_segment(&mut reorg_segment_ids, output.slot_index)?;
                }
            }
        }

        let (reclaimed_tx_hashes, reverted_heights) = {
            if ancestor_height != 0 && self.store.get_undo_log(ancestor_height)?.is_none() {
                return Err(MdbxContextError::Corrupt("reorg ancestor undo log missing"));
            }
            let old_tip_height = self.tip_height;
            for height in (ancestor_height + 1..=old_tip_height).rev() {
                match self.store.get_undo_log(height) {
                    Ok(Some(undo)) => {
                        for &(slot_index, _) in &undo.slot_changes {
                            track_reorg_segment(&mut reorg_segment_ids, slot_index)?;
                        }
                    }
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

            // -----------------------------------------------------------------------
            // Revert blocks from tip to ancestor (RAM only).
            // Safe to execute: all undo logs were validated above.  Read them
            // again one at a time so peak RAM is one decoded undo log instead
            // of the complete finality window.
            // -----------------------------------------------------------------------
            let mut reclaimed_tx_hashes = Vec::new();
            let mut reverted_heights = Vec::new();

            let revert_result = (|| -> Result<(), MdbxContextError> {
                for height in (ancestor_height + 1..=old_tip_height).rev() {
                    let undo =
                        self.store
                            .get_undo_log(height)?
                            .ok_or(MdbxContextError::Corrupt(
                                "validated reorg undo disappeared",
                            ))?;
                    Self::preload_segments_for_undo_in_state(&self.store, &mut self.state, &undo)?;
                    reclaimed_tx_hashes.extend_from_slice(&undo.tx_hashes);
                    revert_block(&mut self.state.state, &undo);
                    self.state
                        .state
                        .shrink_to_log_slots(undo.log_slots_before as usize)
                        .map_err(|_| {
                            MdbxContextError::Corrupt("state shrink after reorg failed")
                        })?;
                    revert_state_counters(&mut self.state, &undo);
                    self.state.rebuild_exact_utxo_root_loaded().map_err(|_| {
                        MdbxContextError::Corrupt("exact root rebuild after reorg failed")
                    })?;
                    let parent_header = self
                        .store
                        .get_header(height - 1)?
                        .ok_or(MdbxContextError::Corrupt("reorg parent header missing"))?;
                    if undo.log_slots_before != parent_header.log_slots
                        || self.state.state.log_slots() as u32 != parent_header.log_slots
                        || self.state.utxo_root != parent_header.state_root
                        || self.state.active_slot_count != parent_header.active_slot_count
                        || self.state.alloc_counter != parent_header.alloc_counter
                    {
                        return Err(MdbxContextError::Corrupt(
                            "reorg undo does not restore parent header state",
                        ));
                    }
                    self.recent_headers.remove(&height);
                    reverted_heights.push(height);
                }
                Ok(())
            })();
            if let Err(error) = revert_result {
                return Err(self.abort_staged_reorg(error));
            }
            (reclaimed_tx_hashes, reverted_heights)
        };

        // -----------------------------------------------------------------------
        // Update tip pointers to the ancestor.
        // -----------------------------------------------------------------------
        self.tip_height = ancestor_height;
        self.tip_hash = block_id(&ancestor_header);
        self.tip_chain_work = ancestor_chain_work;

        // -----------------------------------------------------------------------
        // Validate the entire fork through the normal proof-native applier,
        // but stage every resulting commit in RAM.  The old canonical MDBX
        // branch remains untouched until every replacement block succeeds.
        // -----------------------------------------------------------------------
        let mut applied_heights: Vec<u64> = Vec::new();
        self.defer_finality_updates = true;
        self.reorg_staging = Some(Vec::with_capacity(replacement.len()));

        for candidate in replacement {
            match apply_block(self, candidate, local_time) {
                Ok(()) => {
                    applied_heights.push(candidate.block.header.height);
                    tracing::info!(
                        height = candidate.block.header.height,
                        "reorg: applied new block"
                    );
                }
                Err(e) => {
                    tracing::error!(height = candidate.block.header.height, err = ?e, "reorg: failed to apply block");
                    return Err(self.abort_staged_reorg(e));
                }
            }
        }

        let staged = match self.reorg_staging.take() {
            Some(staged) => staged,
            None => {
                return Err(
                    self.abort_staged_reorg(MdbxContextError::Corrupt("reorg staging disappeared"))
                );
            }
        };
        let finalized_after_reorg = match self.finalized_for_tip(self.tip_height) {
            Ok(finalized) => finalized,
            Err(error) => {
                return Err(self.abort_staged_reorg(error));
            }
        };
        let final_header = *self.tip_header();
        let final_hash = self.tip_hash;
        let consensus_meta = ConsensusMeta {
            tip_height: self.tip_height,
            tip_hash: final_hash,
            cumulative_chainwork: self.tip_chain_work,
            finalized: finalized_after_reorg,
        };
        let commit_result = (|| -> Result<(), MdbxContextError> {
            let dirty_ids: Vec<u16> = self.state.state.dirty_segment_ids().collect();
            let eff_log = self.state.state.effective_log_segment_size() as u8;
            let mut dirty_refs = Vec::with_capacity(dirty_ids.len());
            for segment_id in dirty_ids {
                let columns = if self.state.state.segment_live_count(segment_id) == 0 {
                    None
                } else {
                    Some(self.state.state.try_get_segment_columns(segment_id).ok_or(
                        MdbxContextError::Corrupt("dirty reorg segment is not resident"),
                    )?)
                };
                dirty_refs.push((segment_id, eff_log, columns));
            }
            self.store.commit_reorg(
                ancestor_height,
                &final_header,
                &final_hash,
                &dirty_refs,
                &reclaimed_tx_hashes,
                replacement,
                &staged,
                &consensus_meta,
            )?;
            Ok(())
        })();
        if let Err(error) = commit_result {
            return Err(self.abort_staged_reorg(error));
        }
        self.state.state.clear_dirty();
        self.state.state.evict_all_persisted_segments();
        self.finalized = finalized_after_reorg;
        self.defer_finality_updates = false;

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

    fn preload_segments_for_undo_in_state(
        store: &MdbxStore,
        state: &mut ChainState,
        undo: &BlockUndoLog,
    ) -> Result<(), MdbxContextError> {
        let effective_log = state.state.effective_log_segment_size();
        let mut needed: Vec<u16> = undo
            .slot_changes
            .iter()
            .map(|(slot_index, _)| (*slot_index >> effective_log) as u16)
            .collect();
        needed.sort_unstable();
        needed.dedup();
        for segment_id in needed {
            if !state.state.is_evicted(segment_id) {
                continue;
            }
            let (_, columns) = store
                .get_segment(segment_id)?
                .ok_or(MdbxContextError::Corrupt(
                    "evicted undo segment is missing from MDBX",
                ))?;
            state
                .restore_evicted_segment(segment_id, columns)
                .map_err(|_| {
                    MdbxContextError::Corrupt("evicted undo segment exact summary mismatch")
                })?;
        }
        Ok(())
    }

    /// Preload evicted segments that the block will access.
    ///
    /// Checks each input slot (must be non-empty = need to read existing data)
    /// and each output slot (must be empty = need to read to verify).
    /// Reloads from MDBX any segment that is currently evicted.
    pub fn preload_segments_for_block(&mut self, block: &Block) -> Result<(), MdbxContextError> {
        // Keep the public preload helper fail-closed even when a caller does
        // not come through `apply_next_block`.
        crate::consensus::validate_block_resource_preflight(block)?;
        self.preload_segments_for_preflighted_block(block)
    }

    fn preload_segments_for_preflighted_block(
        &mut self,
        block: &Block,
    ) -> Result<(), MdbxContextError> {
        let eff_log = self.state.state.effective_log_segment_size();
        let mut needed: std::collections::HashSet<u16> = std::collections::HashSet::new();

        for tx in &block.transactions {
            for (_, inp) in tx.body.live_inputs() {
                needed.insert((inp.slot_index >> eff_log) as u16);
            }
            for (_, out) in tx.body.live_outputs() {
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
                        self.state
                            .restore_evicted_segment(seg_id, cols)
                            .map_err(|_| {
                                MdbxContextError::Corrupt("evicted segment exact summary mismatch")
                            })?;
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

    /// Atomically install a finalized disk-staged snapshot and switch the hot
    /// context to a metadata-only exact state.
    ///
    /// `staging` must come from the authenticated receiver staging state
    /// machine. This boundary deliberately accepts no caller-supplied height,
    /// root, counters, or segment vectors: all state identity comes from the
    /// authenticated metadata and locally persisted canonical headers.
    pub fn apply_staged_state_snapshot(
        &mut self,
        staging: &FinalizedSnapshotStaging,
        recent_headers_bytes: &[Vec<u8>],
    ) -> Result<(), MdbxContextError> {
        if self.reorg_staging.is_some() {
            return Err(MdbxContextError::Corrupt(
                "snapshot install cannot run during reorg staging",
            ));
        }

        let authenticated = staging.metadata();
        let tip_header = *authenticated.header();
        let tip_height = tip_header.height;
        let tip_hash = authenticated.tip_hash();
        if tip_height <= self.tip_height {
            return Err(MdbxContextError::Corrupt(
                "snapshot tip is not ahead of local state",
            ));
        }
        if block_id(&tip_header) != tip_hash {
            return Err(MdbxContextError::Corrupt(
                "staged snapshot tip hash does not match authenticated header",
            ));
        }
        let stored_tip_header =
            self.store
                .get_header(tip_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "staged snapshot tip header is missing from canonical store",
                ))?;
        if stored_tip_header != tip_header {
            return Err(MdbxContextError::Corrupt(
                "staged snapshot tip header conflicts with canonical store",
            ));
        }

        // Keep exactly the bounded header window used by MTP, expansion and
        // transaction-epoch checks. Requiring the complete suffix avoids a
        // successful install followed by fallback-to-tip header semantics.
        let history_window = MEDIAN_TIME_BLOCKS as u64 + TX_EPOCH_BLOCKS;
        let expected_first = tip_height.saturating_sub(history_window);
        let expected_header_count =
            tip_height.saturating_sub(expected_first).saturating_add(1) as usize;
        if recent_headers_bytes.len() != expected_header_count {
            return Err(MdbxContextError::Corrupt(
                "staged snapshot recent header window has wrong length",
            ));
        }

        let mut decoded_recent = Vec::with_capacity(expected_header_count);
        for bytes in recent_headers_bytes {
            decoded_recent.push(BlockHeader::from_bytes(bytes).map_err(|_| {
                MdbxContextError::Corrupt("staged snapshot recent header decode failed")
            })?);
        }
        if decoded_recent.first().map(|header| header.height) != Some(expected_first)
            || decoded_recent.last().copied() != Some(tip_header)
        {
            return Err(MdbxContextError::Corrupt(
                "staged snapshot recent headers do not cover the required boundary",
            ));
        }
        for pair in decoded_recent.windows(2) {
            if pair[1].height != pair[0].height.saturating_add(1)
                || pair[1].prev_block_hash != block_id(&pair[0])
            {
                return Err(MdbxContextError::Corrupt(
                    "staged snapshot recent headers are not canonical and contiguous",
                ));
            }
        }
        for header in &decoded_recent {
            if self.store.get_header(header.height)? != Some(*header) {
                return Err(MdbxContextError::Corrupt(
                    "staged snapshot recent header conflicts with canonical store",
                ));
            }
        }

        let cumulative_chainwork =
            self.store
                .get_chain_work(tip_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "staged snapshot tip chainwork is missing",
                ))?;
        let finalized = FinalizedCheckpoint {
            height: tip_height,
            hash: tip_hash,
        };
        let consensus_meta = ConsensusMeta {
            tip_height,
            tip_hash,
            cumulative_chainwork,
            finalized,
        };
        let mut recent_headers = HashMap::with_capacity(decoded_recent.len());
        for &header in &decoded_recent {
            recent_headers.insert(header.height, header);
        }

        // The installer returns a compact state only after the single RW
        // transaction has committed. Every operation below is an infallible
        // in-memory swap, so no post-commit error can leave hot and durable
        // state at different boundaries.
        let snapshot_state = self.store.install_finalized_snapshot_staging(
            staging,
            &consensus_meta,
            &decoded_recent,
        )?;
        debug_assert_eq!(snapshot_state.state.materialized_segment_ids().count(), 0);

        self.state = snapshot_state;
        self.recent_headers = recent_headers;
        self.tip_height = tip_height;
        self.tip_hash = tip_hash;
        self.tip_chain_work = cumulative_chainwork;
        self.finalized = finalized;
        self.defer_finality_updates = false;
        Ok(())
    }

    /// Apply a full state snapshot received from a peer during initial sync.
    ///
    /// The caller must already have validated and persisted the canonical header
    /// chain through `tip_height` and accepted the snapshot proof policy.
    #[cfg(test)]
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
    /// the bounded recent window (≥ EXPANSION_WINDOW).
    pub fn prev_active_counts(&self) -> Vec<u64> {
        let tip = self.tip_height;
        let start = tip.saturating_sub(EXPANSION_WINDOW.saturating_sub(1));
        (start..=tip)
            .filter_map(|h| self.recent_headers.get(&h).map(|hdr| hdr.active_slot_count))
            .collect()
    }

    pub fn anchor_info(&self) -> AnchorInfo {
        let anchor_height = asert_anchor_height(self.tip_height);
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

    /// Check exact equality with the start anchor for the next child block.
    pub fn is_current_tx_epoch_anchor(&self, anchor_hash: &[u8; 32]) -> bool {
        let height = tx_epoch_anchor_height_for_child(self.tip_height + 1);
        self.get_header_from_store(height)
            .ok()
            .flatten()
            .is_some_and(|header| block_id(&header) == *anchor_hash)
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{compute_tx_root, Block};
    use crate::chain_context::TEST_TARGET;
    use crate::consensus::{emission::block_reward, params::BLOCK_TIME};
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    #[test]
    fn reorg_resident_segment_budget_is_bounded_before_mutation() {
        let mut segment_ids = std::collections::HashSet::new();

        for segment_id in 0..MAX_REORG_RESIDENT_SEGMENTS {
            track_reorg_segment(&mut segment_ids, (segment_id as u32) << LOG_SEGMENT_SIZE).unwrap();
        }

        // Repeated slots in an already resident segment consume no extra RAM
        // budget.
        track_reorg_segment(&mut segment_ids, 1).unwrap();

        let error = track_reorg_segment(
            &mut segment_ids,
            (MAX_REORG_RESIDENT_SEGMENTS as u32) << LOG_SEGMENT_SIZE,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MdbxContextError::ResourceLimit {
                resource: "reorg resident segments",
                actual,
                maximum,
            } if actual == MAX_REORG_RESIDENT_SEGMENTS + 1
                && maximum == MAX_REORG_RESIDENT_SEGMENTS
        ));
    }

    fn coinbase_block(ctx: &MdbxChainContext, slot: u32, owner: Address) -> Block {
        let parent = *ctx.tip_header();
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: slot,
            amount: block_reward(parent.log_slots),
            owner,
        };
        let tx = Transaction::new(TxBody {
            epoch_anchor: block_id(&parent),
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        });
        let mut child = ctx.state.clone();
        let segment_id = (slot >> child.state.effective_log_segment_size()) as u16;
        if child.state.is_evicted(segment_id) {
            let (_, columns) = ctx.store.get_segment(segment_id).unwrap().unwrap();
            child.restore_evicted_segment(segment_id, columns).unwrap();
        }
        crate::state::apply_tx(&mut child, &tx.body).unwrap();
        Block {
            header: BlockHeader {
                prev_block_hash: block_id(&parent),
                state_root: child.state_root(),
                tx_root: compute_tx_root(std::slice::from_ref(&tx)),
                timestamp: parent.timestamp + BLOCK_TIME,
                height: parent.height + 1,
                miner_address: owner,
                nonce: 0,
                difficulty_target: TEST_TARGET,
                log_slots: parent.log_slots,
                active_slot_count: child.active_slot_count,
                alloc_counter: child.alloc_counter,
            },
            transactions: vec![tx],
        }
    }

    fn apply_coinbase(
        ctx: &mut MdbxChainContext,
        block: &Block,
    ) -> Result<[u8; 32], MdbxContextError> {
        ctx.apply_next_block(
            block,
            &[],
            &[],
            block.header.timestamp + 1,
            |block,
             _proof,
             _sidecar,
             _parent,
             _timestamps,
             _active,
             _local,
             _tx_epoch,
             _anchor,
             state|
             -> Result<AppliedBlockValidation, String> {
                crate::block::apply_block(state, block)
                    .map(|transition| {
                        AppliedBlockValidation::new(
                            transition.new_state_root,
                            b"test-history-claim".to_vec(),
                            b"test-accepted-certificate".to_vec(),
                        )
                    })
                    .map_err(|error| format!("{error:?}"))
            },
        )
    }

    #[test]
    fn staged_snapshot_context_switches_to_compact_state_and_restarts_consistently() {
        use crate::consensus::da_prune::BlockUndoLog;
        use crate::fri_state::{compute_segment_root, SlotValue};
        use crate::segmented_state::SegmentColumns;
        use crate::storage::{
            AuthenticatedSnapshotMetadata, SnapshotSegmentDescriptor, SnapshotStagingSession,
        };

        let database = tempfile::tempdir().unwrap();
        let staging_parent = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(database.path()).unwrap();
        let empty_state = ChainState::with_log_slots(3);
        let mut genesis = crate::consensus::genesis::genesis_header();
        genesis.log_slots = 3;
        genesis.active_slot_count = 0;
        genesis.alloc_counter = 0;
        genesis.state_root = empty_state.utxo_root;
        let genesis_hash = block_id(&genesis);
        let genesis_finalized = FinalizedCheckpoint {
            height: 0,
            hash: genesis_hash,
        };
        let genesis_meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: genesis_hash,
            cumulative_chainwork: [1; 32],
            finalized: genesis_finalized,
        };
        store
            .commit_block(
                &genesis,
                &genesis_hash,
                &BlockUndoLog::empty(0, 3),
                &[],
                &[],
                &[],
                None,
                None,
                &genesis_meta,
                false,
            )
            .unwrap();
        let mut initial_headers = HashMap::new();
        initial_headers.insert(0, genesis);
        let mut ctx = MdbxChainContext {
            store,
            state: empty_state,
            recent_headers: initial_headers,
            tip_height: 0,
            tip_hash: genesis_hash,
            tip_chain_work: [1; 32],
            finalized: genesis_finalized,
            defer_finality_updates: false,
            reorg_staging: None,
        };

        let owner = Address([0x81; 32]);
        let live = SlotValue::with_owner_fields(99, 1, owner.as_fields());
        let target_state = ChainState::from_sparse_utxos(3, &[(5, live)], 1).unwrap();
        let mut target = genesis;
        target.height = 1;
        target.prev_block_hash = genesis_hash;
        target.timestamp = target.timestamp.saturating_add(1);
        target.state_root = target_state.utxo_root;
        target.active_slot_count = 1;
        target.alloc_counter = 1;
        let target_hash = block_id(&target);
        ctx.store
            .put_verified_header_only(&target, &target_hash, &[2; 32])
            .unwrap();

        let mut columns = SegmentColumns::new_zero(8);
        columns.values[5] = live.value;
        columns.owners_hi[5] = live.owner_hi;
        columns.owners_lo[5] = live.owner_lo;
        let encoded = encode_segment(&columns, 3);
        let descriptor = SnapshotSegmentDescriptor {
            segment_id: 0,
            segment_root: compute_segment_root(
                3,
                &columns.values,
                &columns.owners_hi,
                &columns.owners_lo,
            ),
            encoded_len: encoded.len() as u32,
        };
        let authenticated =
            AuthenticatedSnapshotMetadata::from_authenticated_header(target, target_hash, 3)
                .unwrap();
        let mut session =
            SnapshotStagingSession::new(staging_parent.path(), authenticated, vec![descriptor])
                .unwrap();
        session.accept_segment(0, 3, &encoded).unwrap();
        let staging = session.finalize().unwrap();
        let recent_headers = vec![genesis.to_bytes().to_vec(), target.to_bytes().to_vec()];

        ctx.apply_staged_state_snapshot(&staging, &recent_headers)
            .unwrap();
        assert_eq!(ctx.tip_height(), 1);
        assert_eq!(ctx.tip_hash(), target_hash);
        assert_eq!(ctx.state.cached_state_root(), target.state_root);
        assert_eq!(ctx.state.state.materialized_segment_ids().count(), 0);
        assert!(ctx.state.state.is_evicted(0));
        assert_eq!(ctx.store.get_undo_log(0).unwrap(), None);
        assert_eq!(
            ctx.store
                .get_verified_utxos_by_owner(&owner.0)
                .unwrap()
                .utxos,
            vec![crate::storage::VerifiedOwnerUtxo {
                slot_index: 5,
                amount: 99,
                creation_id: 1,
            }]
        );

        drop(staging);
        drop(ctx);
        let reopened_store = MdbxStore::open(database.path()).unwrap();
        let reopened = MdbxChainContext::restore_from_mdbx(reopened_store).unwrap();
        assert_eq!(reopened.tip_height(), 1);
        assert_eq!(reopened.tip_hash(), target_hash);
        assert_eq!(reopened.state.cached_state_root(), target.state_root);
        assert_eq!(reopened.state.state.materialized_segment_ids().count(), 0);
        assert!(reopened.state.state.is_evicted(0));
    }

    #[test]
    fn fresh_database_has_canonical_genesis_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(ctx.tip_height(), 0);
        let header = *ctx.tip_header();
        let expected =
            crate::compute_header_chain_anchor(std::iter::once(&header), *ctx.tip_chain_work())
                .unwrap();
        assert_eq!(ctx.store.get_header_anchor(0).unwrap(), Some(expected));
    }

    #[test]
    fn coinbase_commit_tx_index_and_restart_are_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let txid;
        let root;
        {
            let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
            let block = coinbase_block(&ctx, 7, Address([1u8; 32]));
            txid = block.transactions[0].txid();
            root = apply_coinbase(&mut ctx, &block).unwrap();
            assert_eq!(ctx.state.state.materialized_segment_ids().count(), 0);
            assert_eq!(ctx.store.get_tx_index(&txid.0).unwrap(), Some((1, 0)));
            assert_eq!(
                ctx.store.get_history_claim(1).unwrap().as_deref(),
                Some(b"test-history-claim".as_slice())
            );
            assert_eq!(
                ctx.store
                    .get_accepted_block_certificate(1)
                    .unwrap()
                    .as_deref(),
                Some(b"test-accepted-certificate".as_slice())
            );
            assert_eq!(ctx.store.get_block_proof(1).unwrap(), None);
            assert_eq!(ctx.store.get_block_auth_sidecar(1).unwrap(), None);
        }
        let reopened = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        assert_eq!(reopened.tip_height(), 1);
        assert_eq!(reopened.state.cached_state_root(), root);
        assert_eq!(reopened.state.state.materialized_segment_ids().count(), 0);
        assert_eq!(reopened.store.get_tx_index(&txid.0).unwrap(), Some((1, 0)));
        assert_eq!(
            reopened.store.get_history_claim(1).unwrap().as_deref(),
            Some(b"test-history-claim".as_slice())
        );
        assert_eq!(
            reopened
                .store
                .get_accepted_block_certificate(1)
                .unwrap()
                .as_deref(),
            Some(b"test-accepted-certificate".as_slice())
        );
    }

    #[test]
    fn occupied_coinbase_slot_rejects_without_poisoning_tip() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        let first = coinbase_block(&ctx, 7, Address([1u8; 32]));
        apply_coinbase(&mut ctx, &first).unwrap();
        let tip = ctx.tip_hash();
        let root = ctx.state.cached_state_root();

        let parent = *ctx.tip_header();
        let mut bad = coinbase_block(&ctx, 8, Address([2u8; 32]));
        bad.transactions[0].body.outputs[0].slot_index = 7;
        bad.header.tx_root = compute_tx_root(&bad.transactions);
        let mut blind = ctx.state.clone();
        blind.alloc_counter += 1;
        blind.active_slot_count += 1;
        blind
            .state
            .set_slot(
                7,
                crate::fri_state::SlotValue::with_owner_fields(
                    bad.transactions[0].body.outputs[0].amount,
                    blind.alloc_counter,
                    Address([2u8; 32]).as_fields(),
                ),
            )
            .unwrap();
        bad.header.state_root = blind.state_root();
        bad.header.active_slot_count = blind.active_slot_count;
        bad.header.alloc_counter = blind.alloc_counter;
        bad.header.prev_block_hash = block_id(&parent);

        assert!(apply_coinbase(&mut ctx, &bad).is_err());
        assert_eq!(ctx.tip_hash(), tip);
        assert_eq!(ctx.state.cached_state_root(), root);
    }

    #[test]
    fn direct_block_with_wrong_user_epoch_anchor_fails_before_apply() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = MdbxChainContext::open_or_create_for_test(dir.path()).unwrap();
        let mut block = coinbase_block(&ctx, 7, Address([1u8; 32]));
        let mut user_inputs = [TxInput::dummy(); TX_INPUTS];
        user_inputs[0] = TxInput {
            slot_index: 9,
            amount: 2,
            creation_id: 1,
        };
        let mut user_outputs = [TxOutput::dummy(); TX_OUTPUTS];
        user_outputs[0] = TxOutput {
            slot_index: 10,
            amount: 1,
            owner: Address([3u8; 32]),
        };
        block.transactions.push(Transaction::new(TxBody {
            epoch_anchor: [0xAA; 32],
            fee: 1,
            input_owner: Address([3u8; 32]),
            inputs: user_inputs,
            outputs: user_outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }));
        block.header.tx_root = compute_tx_root(&block.transactions);
        assert!(matches!(
            apply_coinbase(&mut ctx, &block),
            Err(MdbxContextError::Consensus(ConsensusError::BadEpochAnchor))
        ));
        assert_eq!(ctx.tip_height(), 0);
    }

    #[test]
    fn failed_multi_block_reorg_leaves_ram_and_mdbx_on_old_branch() {
        let canonical_dir = tempfile::tempdir().unwrap();
        let replacement_dir = tempfile::tempdir().unwrap();
        let mut canonical =
            MdbxChainContext::open_or_create_for_test(canonical_dir.path()).unwrap();
        let old_one = coinbase_block(&canonical, 7, Address([1u8; 32]));
        apply_coinbase(&mut canonical, &old_one).unwrap();
        let old_two = coinbase_block(&canonical, 8, Address([1u8; 32]));
        apply_coinbase(&mut canonical, &old_two).unwrap();
        let old_one_hash = block_id(&old_one.header);
        let old_two_hash = block_id(&old_two.header);
        let claimed = canonical
            .store
            .claim_next_recursive_proof_job()
            .unwrap()
            .unwrap();
        assert_eq!((claimed.height, claimed.block_hash), (1, old_one_hash));
        canonical
            .store
            .complete_recursive_proof_job(1, old_one_hash, b"old-selected-proof")
            .unwrap();
        let old_tip = canonical.tip_hash();
        let old_root = canonical.state.cached_state_root();
        let old_txid = old_two.transactions[0].txid();

        let mut replacement =
            MdbxChainContext::open_or_create_for_test(replacement_dir.path()).unwrap();
        let replacement_one = coinbase_block(&replacement, 9, Address([2u8; 32]));
        apply_coinbase(&mut replacement, &replacement_one).unwrap();
        let mut replacement_two = coinbase_block(&replacement, 10, Address([2u8; 32]));
        replacement_two.header.prev_block_hash = [0xA5; 32];
        let replacement_txid = replacement_one.transactions[0].txid();
        let payloads = [
            ReorgBlockPayload::new(&replacement_one, &[], &[]),
            ReorgBlockPayload::new(&replacement_two, &[], &[]),
        ];

        let result = canonical.apply_reorg_mdbx_with_applier(
            0,
            &payloads,
            replacement_two.header.timestamp + 1,
            |ctx, candidate, _local_time| apply_coinbase(ctx, candidate.block).map(|_| ()),
        );
        assert!(result.is_err());
        assert_eq!(canonical.tip_height(), 2);
        assert_eq!(canonical.tip_hash(), old_tip);
        assert_eq!(canonical.state.cached_state_root(), old_root);
        assert_eq!(
            canonical.store.get_tx_index(&old_txid.0).unwrap(),
            Some((2, 0))
        );
        assert_eq!(
            canonical.store.get_tx_index(&replacement_txid.0).unwrap(),
            None
        );
        let preserved_job_one = canonical.store.get_recursive_proof_job(1).unwrap().unwrap();
        assert_eq!(preserved_job_one.block_hash, old_one_hash);
        assert_eq!(
            preserved_job_one.state,
            crate::storage::RecursiveProofJobState::Complete
        );
        assert_eq!(
            canonical
                .store
                .get_recursive_proof_job_result(1)
                .unwrap()
                .unwrap()
                .bytes,
            b"old-selected-proof"
        );
        let preserved_job_two = canonical.store.get_recursive_proof_job(2).unwrap().unwrap();
        assert_eq!(preserved_job_two.block_hash, old_two_hash);
        assert_eq!(
            preserved_job_two.state,
            crate::storage::RecursiveProofJobState::Pending
        );
        drop(canonical);

        let reopened = MdbxChainContext::open_or_create_for_test(canonical_dir.path()).unwrap();
        assert_eq!(reopened.tip_height(), 2);
        assert_eq!(reopened.tip_hash(), old_tip);
        assert_eq!(reopened.state.cached_state_root(), old_root);
        assert_eq!(
            reopened.store.get_tx_index(&old_txid.0).unwrap(),
            Some((2, 0))
        );
        assert_eq!(
            reopened.store.get_tx_index(&replacement_txid.0).unwrap(),
            None
        );
        assert_eq!(
            reopened
                .store
                .get_recursive_proof_job_result(1)
                .unwrap()
                .unwrap()
                .bytes,
            b"old-selected-proof"
        );
        assert_eq!(
            reopened
                .store
                .get_recursive_proof_job(2)
                .unwrap()
                .unwrap()
                .block_hash,
            old_two_hash
        );
    }

    #[test]
    fn successful_multi_block_reorg_commits_one_restart_consistent_suffix() {
        let canonical_dir = tempfile::tempdir().unwrap();
        let replacement_dir = tempfile::tempdir().unwrap();
        let mut canonical =
            MdbxChainContext::open_or_create_for_test(canonical_dir.path()).unwrap();
        let old_one = coinbase_block(&canonical, 7, Address([1u8; 32]));
        apply_coinbase(&mut canonical, &old_one).unwrap();
        let old_two = coinbase_block(&canonical, 8, Address([1u8; 32]));
        apply_coinbase(&mut canonical, &old_two).unwrap();
        let old_one_hash = block_id(&old_one.header);
        let claimed = canonical
            .store
            .claim_next_recursive_proof_job()
            .unwrap()
            .unwrap();
        assert_eq!((claimed.height, claimed.block_hash), (1, old_one_hash));
        canonical
            .store
            .complete_recursive_proof_job(1, old_one_hash, b"stale-selected-proof")
            .unwrap();
        let old_txid = old_two.transactions[0].txid();

        let mut replacement =
            MdbxChainContext::open_or_create_for_test(replacement_dir.path()).unwrap();
        let replacement_one = coinbase_block(&replacement, 9, Address([2u8; 32]));
        apply_coinbase(&mut replacement, &replacement_one).unwrap();
        let replacement_two = coinbase_block(&replacement, 10, Address([2u8; 32]));
        apply_coinbase(&mut replacement, &replacement_two).unwrap();
        let replacement_one_txid = replacement_one.transactions[0].txid();
        let replacement_two_txid = replacement_two.transactions[0].txid();
        let expected_tip = block_id(&replacement_two.header);
        let expected_root = replacement_two.header.state_root;
        let payloads = [
            ReorgBlockPayload::new(&replacement_one, &[], &[]),
            ReorgBlockPayload::new(&replacement_two, &[], &[]),
        ];

        let result = canonical
            .apply_reorg_mdbx_with_applier(
                0,
                &payloads,
                replacement_two.header.timestamp + 1,
                |ctx, candidate, _local_time| apply_coinbase(ctx, candidate.block).map(|_| ()),
            )
            .unwrap();
        assert_eq!(result.reverted_heights, vec![2, 1]);
        assert_eq!(result.applied_heights, vec![1, 2]);
        assert_eq!(canonical.tip_hash(), expected_tip);
        assert_eq!(canonical.state.cached_state_root(), expected_root);
        assert_eq!(canonical.store.get_tx_index(&old_txid.0).unwrap(), None);
        assert_eq!(
            canonical
                .store
                .get_tx_index(&replacement_one_txid.0)
                .unwrap(),
            Some((1, 0))
        );
        assert_eq!(
            canonical
                .store
                .get_tx_index(&replacement_two_txid.0)
                .unwrap(),
            Some((2, 0))
        );
        assert!(canonical
            .store
            .get_recursive_proof_job_result(1)
            .unwrap()
            .is_none());
        for (height, expected_hash) in [
            (1, block_id(&replacement_one.header)),
            (2, block_id(&replacement_two.header)),
        ] {
            let job = canonical
                .store
                .get_recursive_proof_job(height)
                .unwrap()
                .unwrap();
            assert_eq!(job.block_hash, expected_hash);
            assert_eq!(job.tier, crate::storage::RecursiveProofJobTier::B8);
            assert_eq!(job.state, crate::storage::RecursiveProofJobState::Pending);
        }
        drop(canonical);

        let reopened = MdbxChainContext::open_or_create_for_test(canonical_dir.path()).unwrap();
        assert_eq!(reopened.tip_height(), 2);
        assert_eq!(reopened.tip_hash(), expected_tip);
        assert_eq!(reopened.state.cached_state_root(), expected_root);
        assert_eq!(
            reopened
                .store
                .get_tx_index(&replacement_two_txid.0)
                .unwrap(),
            Some((2, 0))
        );
        assert!(reopened
            .store
            .get_recursive_proof_job_result(1)
            .unwrap()
            .is_none());
        assert_eq!(
            reopened
                .store
                .get_recursive_proof_job(2)
                .unwrap()
                .unwrap()
                .block_hash,
            block_id(&replacement_two.header)
        );
    }
}
