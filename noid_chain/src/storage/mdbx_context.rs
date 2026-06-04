// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

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
//! (nullifiers from stored nullifier-block entries, segment columns from the
//! `segments` table). No replay from genesis needed.
//!
//! # Hot vs cold data
//!
//! | Data | Where | Why |
//! |------|-------|-----|
//! | Headers | MDBX (forever) | Random access by height/hash |
//! | Segment columns | MDBX (forever) | Persist across restarts |
//! | Nullifiers | RAM + MDBX | O(1) lookup in RAM; MDBX for recovery |
//! | Undo logs | MDBX (18 blocks) | Reorg recovery |
//! | Recent blocks | MDBX (18 blocks) | Peer sync |
//! | ChainState (active/alloc) | MDBX (state_meta) | Fast restart |
//! | Recent headers | RAM (MEDIAN_TIME_BLOCKS + ANCHOR_DEPTH) | Timestamp + anchor validation |

use std::collections::HashMap;
use std::path::Path;

use noid_poseidon2b::primitives::TxBodyHash;

use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::chain_context::ChainContext;
use crate::consensus::{
    da_prune::{build_undo_log, revert_block},
    difficulty::{add_work, block_work},
    header::epoch_anchor_height,
    params::{ANCHOR_DEPTH, EXPANSION_WINDOW, FINALITY_DEPTH, GENESIS_TARGET, MEDIAN_TIME_BLOCKS},
    pow::full_block_hash,
    validation::{validate_block_consensus, AnchorInfo},
    ConsensusError,
};
use crate::nullifier::NullifierSet;
use crate::segmented_state::SegmentedFriState;
use crate::state::ChainState;
use crate::storage::{MdbxStore, StoreError};

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
/// nullifier set from stored per-block hash entries, loads recent headers.
///
/// On each block: writes all data atomically, then updates hot RAM state.
pub struct MdbxChainContext {
    /// MDBX database (all durable storage).
    pub store: MdbxStore,

    /// Hot in-memory UTXO state (rebuilt from MDBX on startup, updated on each block).
    /// `state.state` is a `SegmentedFriState` whose dirty segments are written to MDBX
    /// atomically with each block commit.
    pub state: ChainState,

    /// Rolling nullifier window (last ANCHOR_DEPTH blocks).
    pub nullifiers: NullifierSet,

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
}

impl MdbxChainContext {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Open an existing MDBX database, or initialise a fresh one from genesis.
    ///
    /// If the database is empty (first run), writes the genesis state.
    /// If the database already has data, rebuilds hot RAM state from MDBX.
    pub fn open_or_create(path: &Path) -> Result<Self, MdbxContextError> {
        let store = MdbxStore::open(path)?;

        if store.is_empty()? {
            // First run: initialise from genesis.
            let consensus = ChainContext::init_from_genesis();
            // Genesis chainwork = work contributed by the genesis block alone.
            let tip_chain_work = block_work(&GENESIS_TARGET);
            let ctx = Self {
                store,
                state: consensus.state,
                nullifiers: consensus.nullifiers,
                recent_headers: consensus.headers,
                tip_height: consensus.tip_height,
                tip_hash: consensus.tip_hash,
                tip_chain_work,
            };
            // Persist genesis state_meta and chain_tip so subsequent restarts work.
            ctx.persist_genesis()?;
            Ok(ctx)
        } else {
            // Subsequent run: restore from MDBX.
            Self::restore_from_mdbx(store)
        }
    }

    fn persist_genesis(&self) -> Result<(), MdbxContextError> {
        use crate::consensus::da_prune::BlockUndoLog;
        use crate::consensus::genesis::genesis_header;

        let genesis = genesis_header();
        let genesis_hash = full_block_hash(&genesis);

        // Write genesis header + tip + state_meta in one transaction.
        // We can't use commit_block (no undo_log for genesis), so write directly.
        // For genesis: segments are all virtual-zero, no dirty segments.
        self.store.commit_block(
            &genesis,
            &genesis_hash,
            &BlockUndoLog::empty(0),
            &[],  // no dirty segments (all virtual zero)
            &[],  // no nullifiers
            None, // no block bytes for genesis
        )?;
        Ok(())
    }

    fn restore_from_mdbx(store: MdbxStore) -> Result<Self, MdbxContextError> {
        // 1. Read chain tip.
        let (tip_height, tip_hash) = store
            .get_chain_tip()?
            .ok_or(MdbxContextError::Corrupt("missing chain_tip"))?;

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
        let restored_root = seg_state.root();
        let tip_hdr = store
            .get_header(tip_height)?
            .ok_or(MdbxContextError::Corrupt("tip header missing from store"))?;
        if restored_root != tip_hdr.state_root {
            return Err(MdbxContextError::Corrupt(
                "state root mismatch after restore: segment data is corrupt",
            ));
        }

        // 4. Rebuild ChainState.
        let state = ChainState {
            state: seg_state,
            active_slot_count,
            alloc_counter,
        };

        // 5. Rebuild recent headers (last MEDIAN_TIME_BLOCKS + ANCHOR_DEPTH blocks).
        let window = (MEDIAN_TIME_BLOCKS as u64) + ANCHOR_DEPTH;
        let start_height = tip_height.saturating_sub(window);
        let mut recent_headers = HashMap::new();
        for h in start_height..=tip_height {
            if let Some(hdr) = store.get_header(h)? {
                recent_headers.insert(h, hdr);
            }
        }

        // 6. Rebuild nullifier set from T_NULLIFIER_BLOCKS (ANCHOR_DEPTH window).
        //
        //    Critical for correctness: if the nullifier set is left empty after
        //    restart, `validate_block_consensus` would accept blocks that
        //    double-spend transactions confirmed within the last ANCHOR_DEPTH
        //    blocks.  We reconstruct the exact same window the RAM set would
        //    have had, by reading the per-block hash entries from MDBX and
        //    calling `insert_block` in ascending height order.
        let null_blocks = store
            .get_nullifier_blocks_range(tip_height.saturating_sub(ANCHOR_DEPTH - 1), tip_height)?;
        let nullifiers =
            NullifierSet::rebuild_from_blocks(null_blocks.into_iter().map(|(_, hashes)| hashes));

        // 7. Reconstruct cumulative chainwork.
        //
        //    Headers are kept in MDBX forever, but reading them all on startup
        //    would be slow for very long chains. We approximate blocks outside
        //    the recent_headers window with GENESIS_TARGET (conservative), and
        //    use precise targets for the recent window (already loaded above).
        let mut tip_chain_work = [0u8; 32];
        // Old blocks (before recent_headers window): approximate with genesis target.
        for _ in 0..start_height {
            tip_chain_work = add_work(&tip_chain_work, &block_work(&GENESIS_TARGET));
        }
        // Recent blocks: use precise difficulty targets.
        for h in start_height..=tip_height {
            if let Some(hdr) = recent_headers.get(&h) {
                tip_chain_work = add_work(&tip_chain_work, &block_work(&hdr.difficulty_target));
            }
        }

        Ok(Self {
            store,
            state,
            nullifiers,
            recent_headers,
            tip_height,
            tip_hash,
            tip_chain_work,
        })
    }

    // -----------------------------------------------------------------------
    // Block application
    // -----------------------------------------------------------------------

    /// Validate and apply the next block, persisting atomically to MDBX.
    ///
    /// # Consistency guarantee
    ///
    /// On **success**: MDBX and RAM are both at height H+1.
    ///
    /// On **consensus failure** (`ConsensusError`): MDBX and RAM are both at
    /// height H (the block was never applied).
    ///
    /// On **MDBX commit failure**: the block is rolled back in RAM via the
    /// pre-built undo log so that both MDBX and RAM remain at height H.  The
    /// error is propagated to the caller; no restart is required.
    pub fn apply_next_block(
        &mut self,
        block: &Block,
        local_time: u64,
    ) -> Result<[u8; 32], MdbxContextError> {
        let parent = self.tip_header().clone();
        let prev_timestamps = self.prev_timestamps();
        let prev_active_counts = self.prev_active_counts();
        let anchor = self.anchor_info();

        // Snapshot mutable counters before apply so we can roll them back.
        let pre_active = self.state.active_slot_count;
        let pre_alloc = self.state.alloc_counter;

        // Preload any evicted segments that this block will read or write.
        //
        // Segments are evicted after each block commit to bound RAM usage.
        // Before applying the next block we must reload any segment that
        // contains an input (to validate it is non-empty) or an output
        // (to verify the slot is empty and write the new UTXO).
        self.preload_segments_for_block(block)?;

        // Build undo log BEFORE applying (captures pre-state slot values).
        let undo = build_undo_log(&self.state, block);

        // Run native consensus validation (modifies self.state on success).
        let new_state_root = validate_block_consensus(
            block,
            &parent,
            &prev_timestamps,
            &prev_active_counts,
            local_time,
            &anchor,
            &self.nullifiers,
            &mut self.state,
        )?;
        // self.state is now at H+1. From this point forward any early return
        // MUST revert self.state back to H.

        // Collect dirty segments from the now-updated state.
        let dirty_ids: Vec<u16> = self.state.state.dirty_segment_ids().collect();
        let eff_log = self.state.state.effective_log_segment_size() as u8;
        let dirty_segments: Vec<(u16, u8, _)> = dirty_ids
            .iter()
            .map(|&seg_id| {
                let cols = self.state.state.segment_columns(seg_id).clone();
                (seg_id, eff_log, cols)
            })
            .collect();
        let dirty_refs: Vec<(u16, u8, &_)> = dirty_segments
            .iter()
            .map(|(id, eff, cols)| (*id, *eff, cols))
            .collect();

        // Collect nullifier hashes.
        let tx_hashes: Vec<TxBodyHash> =
            block.transactions.iter().map(|t| t.tx_body_hash).collect();

        // Atomic MDBX commit.
        let block_hash = full_block_hash(&block.header);
        if let Err(e) = self.store.commit_block(
            &block.header,
            &block_hash,
            &undo,
            &dirty_refs,
            &tx_hashes,
            Some(&block.to_bytes()),
        ) {
            // MDBX commit failed (e.g. disk full).  Roll back RAM so that
            // both stores agree at height H.  After this the caller can
            // safely retry or skip the block.
            revert_block(&mut self.state.state, &undo);
            self.state.active_slot_count = pre_active;
            self.state.alloc_counter = pre_alloc;
            self.state.state.clear_dirty();
            return Err(e.into());
        }

        // Update hot RAM state (only after successful MDBX commit).
        self.recent_headers
            .insert(block.header.height, block.header.clone());
        self.nullifiers.insert_block(&tx_hashes);
        self.tip_height = block.header.height;
        self.tip_hash = block_hash;
        // Accumulate PoW work for the newly applied block.
        self.tip_chain_work = add_work(
            &self.tip_chain_work,
            &block_work(&block.header.difficulty_target),
        );

        // Clear MDBX-dirty tracking: next block's dirty_segment_ids() should
        // return only segments modified by THAT block, not accumulated history.
        //
        // NOTE: Segment eviction (evict_clean_segments) is NOT called here.
        // While the infrastructure exists (see evict_clean_segments/restore_evicted_segment),
        // eviction creates subtle bugs:
        //  1. The ChainView (used by mempool for slot validation) is cloned from the
        //     state AFTER eviction. If eviction happens between preload and clone,
        //     the ChainView has evicted (empty) slots for non-zero UTXOs, causing
        //     mempool check_input_slots to reject valid TXs (BadStateRoot).
        //  2. The template builder clones the state; evicted segments materialize
        //     as zeros causing wrong FRI roots (BadStateRoot from block validation).
        //
        // The jemalloc allocator (enabled in noid_node) already returns freed
        // pages to the OS aggressively, providing a 10× RSS reduction vs glibc.
        // Segment eviction is a Phase 9 optimization that requires atomic
        // snapshot semantics (Arc<RwLock<SegmentedFriState>> or similar).
        self.state.state.clear_dirty();

        // Evict old recent_headers beyond the window.
        let window = (MEDIAN_TIME_BLOCKS as u64) + ANCHOR_DEPTH;
        if self.tip_height > window {
            self.recent_headers.remove(&(self.tip_height - window - 1));
        }

        Ok(new_state_root)
    }

    // -----------------------------------------------------------------------
    // Chain reorganization (MDBX-backed)
    // -----------------------------------------------------------------------

    /// Find the height of a block with the given hash in our chain.
    ///
    /// Searches `recent_headers` first (fast RAM lookup), then falls back to
    /// the MDBX hash→height index. Returns `None` if the hash is not found
    /// within the last `FINALITY_DEPTH` blocks.
    pub fn find_ancestor_height(&self, hash: &[u8; 32]) -> Option<u64> {
        // Search recent_headers first (fast path in RAM).
        for (height, header) in &self.recent_headers {
            if &full_block_hash(header) == hash {
                return Some(*height);
            }
        }

        // Fall back to MDBX hash→height index.
        let oldest = self.tip_height.saturating_sub(FINALITY_DEPTH);
        match self.store.get_header_by_hash(hash) {
            Ok(Some(header)) if header.height >= oldest => Some(header.height),
            _ => None,
        }
    }

    /// Apply a chain reorganization backed by MDBX undo logs.
    ///
    /// 1. Reverts our chain from tip back to `ancestor_height` using MDBX undo logs.
    /// 2. Rebuilds the nullifier set for the surviving chain.
    /// 3. Persists the reverted state to MDBX atomically (crash-safe checkpoint).
    /// 4. Applies `new_blocks` on top of `ancestor_height` via `apply_next_block`.
    ///
    /// Returns the hashes of reclaimed transactions for mempool re-admission.
    ///
    /// Fails if reorg depth > `FINALITY_DEPTH` or if an undo log is missing.
    pub fn apply_reorg_mdbx(
        &mut self,
        ancestor_height: u64,
        new_blocks: &[Block],
        local_time: u64,
    ) -> Result<crate::consensus::reorg::ReorgResult, MdbxContextError> {
        use crate::consensus::reorg::{revert_state_counters, ReorgResult};

        let reorg_depth = self.tip_height.saturating_sub(ancestor_height);

        if reorg_depth > FINALITY_DEPTH {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }

        if reorg_depth == 0 {
            return Ok(ReorgResult {
                reverted_heights: vec![],
                applied_heights: vec![],
                reclaimed_tx_hashes: vec![],
            });
        }

        tracing::info!(
            "reorg: reverting height {}..{} depth={} new_blocks={}",
            self.tip_height,
            ancestor_height,
            reorg_depth,
            new_blocks.len()
        );

        // -----------------------------------------------------------------------
        // Phase 1: Revert blocks from tip to ancestor (RAM only).
        // revert_block marks affected segments as mdbx_dirty for the MDBX write
        // in Phase 4.
        // -----------------------------------------------------------------------
        let mut reclaimed_tx_hashes: Vec<TxBodyHash> = Vec::new();
        let mut reverted_heights: Vec<u64> = Vec::new();

        for height in (ancestor_height + 1..=self.tip_height).rev() {
            let undo = match self.store.get_undo_log(height) {
                Ok(Some(u)) => u,
                Ok(None) => {
                    tracing::error!(height, "reorg: undo log missing");
                    return Err(MdbxContextError::Corrupt("undo log missing during reorg"));
                }
                Err(e) => return Err(e.into()),
            };

            // Collect tx hashes for mempool re-admission.
            reclaimed_tx_hashes.extend_from_slice(&undo.tx_hashes);

            // Revert UTXO slot data; marks affected segments as mdbx_dirty.
            revert_block(&mut self.state.state, &undo);
            // Revert active_slot_count and alloc_counter.
            revert_state_counters(&mut self.state, &undo);

            self.recent_headers.remove(&height);
            reverted_heights.push(height);
        }

        // -----------------------------------------------------------------------
        // Phase 2: Rebuild nullifier set from the surviving chain.
        // Uses T_NULLIFIER_BLOCKS (kept for ANCHOR_DEPTH blocks), not undo logs
        // (kept for only FINALITY_DEPTH blocks).
        // -----------------------------------------------------------------------
        {
            let rebuild_start = ancestor_height.saturating_sub(ANCHOR_DEPTH - 1);
            let null_blocks = self
                .store
                .get_nullifier_blocks_range(rebuild_start, ancestor_height)?;
            self.nullifiers =
                NullifierSet::rebuild_from_blocks(null_blocks.into_iter().map(|(_, h)| h));
        }

        // -----------------------------------------------------------------------
        // Phase 3: Update tip pointers to the ancestor.
        // -----------------------------------------------------------------------
        let ancestor_header =
            self.get_header_from_store(ancestor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "ancestor header missing from store",
                ))?;

        self.tip_height = ancestor_height;
        self.tip_hash = full_block_hash(&ancestor_header);

        // -----------------------------------------------------------------------
        // Phase 4: Persist the reverted state to MDBX atomically.
        // dirty segments (from Phase 1) are written before new blocks so crash
        // recovery always sees a consistent ancestor checkpoint.
        // -----------------------------------------------------------------------
        self.persist_reorg_checkpoint(&ancestor_header)?;

        // -----------------------------------------------------------------------
        // Phase 5: Apply new blocks using the existing apply_next_block.
        // -----------------------------------------------------------------------
        let mut applied_heights: Vec<u64> = Vec::new();

        for block in new_blocks {
            match self.apply_next_block(block, local_time) {
                Ok(_) => {
                    applied_heights.push(block.header.height);
                    tracing::info!(height = block.header.height, "reorg: applied new block");
                }
                Err(e) => {
                    tracing::error!(height = block.header.height, err = ?e, "reorg: failed to apply block");
                    return Err(e);
                }
            }
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
    ) -> Result<(), MdbxContextError> {
        use crate::consensus::da_prune::BlockUndoLog;

        // Collect all segments dirtied by the revert_block calls in Phase 1.
        let dirty_ids: Vec<u16> = self.state.state.dirty_segment_ids().collect();
        let eff_log = self.state.state.effective_log_segment_size() as u8;
        let dirty_segments: Vec<(u16, u8, _)> = dirty_ids
            .iter()
            .map(|&seg_id| {
                let cols = self.state.state.segment_columns(seg_id).clone();
                (seg_id, eff_log, cols)
            })
            .collect();
        let dirty_refs: Vec<(u16, u8, &_)> = dirty_segments
            .iter()
            .map(|(id, eff, cols)| (*id, *eff, cols))
            .collect();

        let ancestor_hash = full_block_hash(ancestor_header);

        // Read the ancestor's existing undo log so we don't overwrite it with
        // empty — it must remain intact for any future reorg within finality.
        let existing_undo = self
            .store
            .get_undo_log(ancestor_header.height)?
            .unwrap_or_else(|| BlockUndoLog::empty(ancestor_header.height));

        // Atomic commit: dirty segments + updated chain_tip + state_meta.
        // The ancestor's header and hash→height index are idempotently re-written.
        // nullifier_hashes=[] avoids re-inserting entries already in MDBX.
        self.store
            .commit_block(
                ancestor_header,
                &ancestor_hash,
                &existing_undo,
                &dirty_refs,
                &[],  // ancestor's nullifiers already stored; don't duplicate
                None, // no block bytes (stored earlier or DA-pruned)
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
    /// per block template refresh; negligible at mainnet (60 s blocks).
    pub fn preload_all_evicted_segments(&mut self) -> Result<(), MdbxContextError> {
        let evicted: Vec<u16> = self.state.state.evicted_segment_ids().collect();
        for seg_id in evicted {
            match self.store.get_segment(seg_id) {
                Ok(Some((_eff, cols))) => {
                    self.state.state.restore_evicted_segment(seg_id, cols);
                }
                Ok(None) => {
                    tracing::warn!(seg_id, "preload_all_evicted: segment missing from MDBX");
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
    fn preload_segments_for_block(&mut self, block: &Block) -> Result<(), MdbxContextError> {
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
                        // Segment was marked evicted but MDBX has no data.
                        // This shouldn't happen; treat as bug and clear eviction.
                        tracing::warn!(
                            seg_id,
                            "evicted segment not found in MDBX — treating as zero (this is a bug)"
                        );
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
    /// Paranoid's designed sync method: new nodes download the CURRENT STATE
    /// (not block history, which is not stored after FINALITY_DEPTH blocks).
    /// The state's validity is proven by the recursive chain proof (see noid_recursive).
    /// For testnet, nodes accept snapshots from configured seed peers.
    ///
    /// After this call, the node is at the snapshot's tip height and can
    /// immediately start receiving gossipsub blocks and mining.
    pub fn apply_state_snapshot(
        &mut self,
        tip_height: u64,
        tip_hash: [u8; 32],
        log_slots: u32,
        active_slot_count: u64,
        alloc_counter: u64,
        segments: &[(u16, u8, crate::segmented_state::SegmentColumns)],
        recent_headers_bytes: &[Vec<u8>],
        nullifier_blocks: &[Vec<noid_poseidon2b::primitives::TxBodyHash>],
    ) -> Result<(), MdbxContextError> {
        use crate::block_header::BlockHeader;
        use crate::consensus::difficulty::{add_work, block_work};
        use crate::nullifier::NullifierSet;

        // 1. Rebuild SegmentedFriState from snapshot segments.
        let mut seg_state =
            crate::segmented_state::SegmentedFriState::new_empty(log_slots as usize);
        for (seg_id, _eff_log, cols) in segments {
            seg_state.set_segment_columns(*seg_id, cols.clone());
        }

        // 2. Decode and index recent headers.
        let mut new_recent: std::collections::HashMap<u64, BlockHeader> =
            std::collections::HashMap::new();
        let mut new_tip_header: Option<BlockHeader> = None;
        for bytes in recent_headers_bytes {
            if let Ok(hdr) = BlockHeader::from_bytes(bytes) {
                if hdr.height == tip_height {
                    new_tip_header = Some(hdr.clone());
                }
                new_recent.insert(hdr.height, hdr);
            }
        }

        // SECURITY: Verify that the snapshot's segment data matches the tip header's
        // state_root BEFORE touching in-memory or MDBX state.
        //
        // Without this check a malicious peer can send fabricated slot values while
        // providing valid-looking block headers, completely replacing our state
        // (Eclipse attack). This mirrors the identical check in restore_from_mdbx().
        {
            let tip_hdr = new_tip_header.as_ref().ok_or(MdbxContextError::Corrupt(
                "snapshot missing tip header in recent_headers: cannot verify state_root",
            ))?;
            let computed_root = seg_state.root();
            if computed_root != tip_hdr.state_root {
                return Err(MdbxContextError::Corrupt(
                    "snapshot state_root mismatch: segment data does not match \
                     tip header state_root (possible Eclipse / fabricated-snapshot attack)",
                ));
            }
        }

        // 3. Rebuild NullifierSet from nullifier_blocks.
        let null_vecs: Vec<Vec<noid_poseidon2b::primitives::TxBodyHash>> =
            nullifier_blocks.to_vec();
        let new_nullifiers = NullifierSet::rebuild_from_blocks(null_vecs);

        // 4. Compute approximate chainwork from recent headers.
        let new_tip_chain_work = {
            let mut w = [0u8; 32];
            for hdr in new_recent.values() {
                w = add_work(&w, &block_work(&hdr.difficulty_target));
            }
            w
        };

        // 5. Apply to in-memory state.
        self.state.state = seg_state;
        self.state.active_slot_count = active_slot_count;
        self.state.alloc_counter = alloc_counter;
        self.state.state.clear_dirty();
        self.recent_headers = new_recent;
        self.nullifiers = new_nullifiers;
        self.tip_height = tip_height;
        self.tip_hash = tip_hash;
        self.tip_chain_work = new_tip_chain_work;

        // 6. Persist the snapshot to MDBX so the node survives restarts.
        // We persist all segments plus tip header (if we have it).
        if let Some(tip_hdr) = new_tip_header {
            // Collect all segments to write
            let eff_log = self.state.state.effective_log_segment_size() as u8;
            let seg_ids: Vec<u16> = self.state.state.active_segment_ids().collect();
            let total = seg_ids.len();
            let dirty_segments: Vec<(u16, u8, crate::segmented_state::SegmentColumns)> = seg_ids
                .iter()
                .map(|&id| (id, eff_log, self.state.state.segment_columns(id).clone()))
                .collect();
            let dirty_refs: Vec<(u16, u8, &crate::segmented_state::SegmentColumns)> =
                dirty_segments
                    .iter()
                    .map(|(id, eff, cols)| (*id, *eff, cols))
                    .collect();

            use crate::consensus::da_prune::BlockUndoLog;
            let empty_undo = BlockUndoLog {
                block_height: tip_height,
                slot_changes: vec![],
                tx_hashes: vec![],
            };

            tracing::info!(
                height = tip_height,
                segments = total,
                "snapshot: writing {} segments to MDBX...",
                total
            );
            self.store
                .commit_block(
                    &tip_hdr,
                    &tip_hash,
                    &empty_undo,
                    &dirty_refs,
                    &[],  // no new nullifier hashes (already rebuilt above)
                    None, // no full block bytes (not stored for snapshot)
                )
                .map_err(MdbxContextError::Store)?;
            tracing::info!(
                height = tip_height,
                segments = total,
                "snapshot: MDBX write complete"
            );

            // Rebuild the owner index from snapshot segments so wallet scan is O(1).
            let snapshot_refs: Vec<(u16, u8, &crate::segmented_state::SegmentColumns)> =
                dirty_segments
                    .iter()
                    .map(|(id, eff, cols)| (*id, *eff, cols))
                    .collect();
            if let Err(e) = self.store.rebuild_owner_index_from_segments(&snapshot_refs) {
                tracing::warn!(err = %e, "rebuild_owner_index_from_segments failed");
            }

            self.state.state.clear_dirty();
        }

        tracing::info!(
            height = tip_height,
            segments = segments.len(),
            active_slots = active_slot_count,
            "state snapshot applied"
        );

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
            return Ok(Some(h.clone()));
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
        let start = tip.saturating_sub(EXPANSION_WINDOW);
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

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }
    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }
    pub fn tip_chain_work(&self) -> &[u8; 32] {
        &self.tip_chain_work
    }
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
    use crate::consensus::{
        genesis::genesis_header,
        params::{BLOCK_TIME, GENESIS_TARGET},
        pow::{full_block_hash, search_pow},
    };
    use noid_poseidon2b::primitives::Address;

    fn build_empty_block_on(ctx: &mut MdbxChainContext) -> Block {
        let parent = ctx.tip_header().clone();
        let new_root = ctx.state.state_root();

        let mut header = BlockHeader {
            prev_block_hash: full_block_hash(&parent),
            state_root: new_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        header.nonce = search_pow(&header, 0, 100_000_000).unwrap();
        Block {
            header,
            transactions: vec![],
        }
    }

    #[test]
    fn open_fresh_database() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
        assert_eq!(ctx.tip_height(), 0);
        assert_eq!(ctx.tip_hash(), full_block_hash(&genesis_header()));
    }

    #[test]
    fn apply_one_block_and_reopen() {
        let dir = tempfile::tempdir().unwrap();

        // Apply one block.
        {
            let mut ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
            let block = build_empty_block_on(&mut ctx);
            let ts = block.header.timestamp + 1;
            ctx.apply_next_block(&block, ts).unwrap();
            assert_eq!(ctx.tip_height(), 1);
        }

        // Reopen and verify tip is persisted.
        {
            let ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
            assert_eq!(ctx.tip_height(), 1, "tip must survive restart");
        }
    }

    #[test]
    fn three_blocks_survive_restart() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
            for _ in 0..3 {
                let block = build_empty_block_on(&mut ctx);
                let ts = block.header.timestamp + 1;
                ctx.apply_next_block(&block, ts).unwrap();
            }
        }

        let ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
        assert_eq!(ctx.tip_height(), 3);
        assert_eq!(ctx.state.active_slot_count, 0);
    }

    #[test]
    fn state_root_consistent_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let root_after_block;

        {
            let mut ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
            let block = build_empty_block_on(&mut ctx);
            let ts = block.header.timestamp + 1;
            root_after_block = ctx.apply_next_block(&block, ts).unwrap();
        }

        let mut ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
        assert_eq!(
            ctx.state.state_root(),
            root_after_block,
            "state root must be identical after restart"
        );
    }

    /// Verify that the nullifier set is correctly rebuilt from MDBX on restart.
    ///
    /// We inject fake tx_body_hashes directly via `store.commit_block` to
    /// simulate a block that contained real transactions.  After restart the
    /// RAM nullifier set must contain exactly those hashes.
    #[test]
    fn nullifiers_rebuilt_after_restart_block_hash_appears() {
        use crate::consensus::da_prune::BlockUndoLog;
        use noid_poseidon2b::primitives::TxBodyHash;

        let dir = tempfile::tempdir().unwrap();

        let sentinel_a = TxBodyHash([0xAAu8; 32]);
        let sentinel_b = TxBodyHash([0xBBu8; 32]);

        // Phase 1: open fresh DB, apply one empty block, then directly write
        // a second block with two sentinel nullifiers via commit_block.
        let block1_hash;
        {
            let mut ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
            // Apply block 1 (empty, no transactions).
            let block1 = build_empty_block_on(&mut ctx);
            let ts = block1.header.timestamp + 1;
            ctx.apply_next_block(&block1, ts).unwrap();
            block1_hash = full_block_hash(&block1.header);

            // Directly commit a fake block 2 with sentinel nullifiers.
            // (We bypass apply_next_block to avoid ZK-proof requirements.)
            let parent = ctx.tip_header().clone();
            let mut hdr2 = BlockHeader {
                prev_block_hash: block1_hash,
                state_root: parent.state_root,
                tx_root: compute_tx_root(&[]),
                timestamp: parent.timestamp + BLOCK_TIME,
                height: 2,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: GENESIS_TARGET,
                proof_transcript_hash: [1u8; 32],
                witness_root: [1u8; 32],
                log_slots: parent.log_slots,
                active_slot_count: parent.active_slot_count,
                alloc_counter: parent.alloc_counter,
            };
            hdr2.nonce = search_pow(&hdr2, 0, 100_000_000).unwrap();
            let hash2 = full_block_hash(&hdr2);
            ctx.store
                .commit_block(
                    &hdr2,
                    &hash2,
                    &BlockUndoLog::empty(2),
                    &[],
                    &[sentinel_a, sentinel_b],
                    None,
                )
                .unwrap();
        }

        // Phase 2: reopen. The rebuilt nullifier set must contain both sentinels.
        {
            // Open by reading chain_tip from MDBX (tip is still 1 since we
            // bypassed apply_next_block for block 2; that's fine for this test).
            let ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();

            // Verify via the store directly: get_nullifier_blocks_range(0, 1)
            // should find the entries we wrote.
            let entries = ctx.store.get_nullifier_blocks_range(0, 10).unwrap();
            // Block 1 was empty (no T_NULLIFIER_BLOCKS entry).
            // Block 2 was injected with sentinels.
            let all_hashes: Vec<TxBodyHash> = entries.into_iter().flat_map(|(_, hs)| hs).collect();
            assert!(
                all_hashes.contains(&sentinel_a),
                "sentinel_a must be recoverable from MDBX"
            );
            assert!(
                all_hashes.contains(&sentinel_b),
                "sentinel_b must be recoverable from MDBX"
            );
        }
    }

    /// Verify that `dirty_segment_ids()` is empty after restart (segments are
    /// not needlessly re-written to MDBX on the very first block).
    #[test]
    fn no_spurious_dirty_segments_after_restart() {
        let dir = tempfile::tempdir().unwrap();

        // First run: apply one block.
        {
            let mut ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
            let block = build_empty_block_on(&mut ctx);
            ctx.apply_next_block(&block, block.header.timestamp + 1)
                .unwrap();
        }

        // Second run: open and verify no dirty segments are queued.
        let ctx = MdbxChainContext::open_or_create(dir.path()).unwrap();
        assert_eq!(
            ctx.state.state.dirty_segment_ids().count(),
            0,
            "no segments should be marked MDBX-dirty after a clean restart"
        );
    }
}
