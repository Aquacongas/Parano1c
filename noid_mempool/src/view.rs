// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `ChainView` — a lightweight snapshot of chain state for mempool admission checks.
//!
//! The view is updated by the node on each new block via `AsyncMempool::on_new_block`.
//! It is intentionally a value type so that admission checks see a consistent snapshot
//! even if a new block arrives concurrently.
//!
//! ## What fits in the view
//!
//! Only data needed for admission:
//! 1. `recent_headers` — epoch_anchor validation
//! 2. `state` — slot liveness and emptiness checks
//! 3. `tip_height` — anchor window bounds
//!
//! The full `SegmentedFriState` is included because it uses lazy segment
//! materialisation — virtual-zero segments are not allocated. At genesis with no
//! activity, a clone costs O(1). Growth is proportional to occupied slots.

use std::collections::HashMap;

use noid_chain::block_header::BlockHeader;
use noid_chain::fri_state::SlotValue;
use noid_chain::segmented_state::SegmentedFriState;

/// A consistent snapshot of chain state used for mempool admission.
#[derive(Clone)]
pub struct ChainView {
    /// Current chain tip height.
    pub tip_height: u64,

    /// Recent block headers (`[tip - ANCHOR_DEPTH, tip]`).
    /// Needed to validate `epoch_anchor` hash against actual headers.
    pub recent_headers: HashMap<u64, BlockHeader>,

    /// Total number of slots in the current state space.
    pub num_slots: u64,

    /// Number of live UTXO slots at the current tip.
    pub active_slot_count: u64,

    /// UTXO state for slot liveness / emptiness checks.
    /// Lazy: only materialized segments are allocated.
    state: SegmentedFriState,
}

impl ChainView {
    /// Construct a `ChainView` from the given state components.
    pub fn new(
        tip_height: u64,
        recent_headers: HashMap<u64, BlockHeader>,
        active_slot_count: u64,
        state: SegmentedFriState,
    ) -> Self {
        let num_slots = state.num_slots();
        Self {
            tip_height,
            recent_headers,
            num_slots,
            active_slot_count,
            state,
        }
    }

    /// Current log2(state_size): number of slot address bits.
    pub fn log_slots(&self) -> u32 {
        self.state.log_slots() as u32
    }

    /// Read the value at global slot index `idx`.
    ///
    /// Returns `SlotValue::EMPTY` for any out-of-range index or virtual-zero segment.
    #[inline]
    pub fn slot(&self, idx: u32) -> SlotValue {
        if (idx as u64) >= self.num_slots {
            return SlotValue::EMPTY;
        }
        self.state.slot(idx)
    }

    /// Build a `ChainView` from a `MdbxChainContext` (call on every new block).
    ///
    /// Clones only the metadata (headers) and the sparse state.
    /// The state clone is cheap when few segments are materialised.
    pub fn from_mdbx(ctx: &noid_chain::storage::MdbxChainContext) -> Self {
        Self::new(
            ctx.tip_height,
            ctx.recent_headers.clone(),
            ctx.state.active_slot_count,
            ctx.state.state.clone(),
        )
    }
}
