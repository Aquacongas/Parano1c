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
//! 1. `recent_headers` — exact transaction-epoch anchor validation
//! 2. `state` — slot liveness and emptiness checks
//! 3. `tip_height` — next-child epoch-boundary selection
//!
//! The full `SegmentedFriState` is included because it uses lazy segment
//! materialisation — virtual-zero segments are not allocated. At genesis with no
//! activity, a clone costs O(1). Growth is proportional to occupied slots.

use std::collections::HashMap;

use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::{pow::block_id, tx_epoch_anchor_height_for_child};
use noid_chain::fri_state::SlotValue;
use noid_chain::segmented_state::SegmentedFriState;

/// A consistent snapshot of chain state used for mempool admission.
#[derive(Clone)]
pub struct ChainView {
    /// Current chain tip height.
    pub tip_height: u64,

    /// Retained block headers needed to resolve the one current transaction
    /// epoch anchor.
    pub recent_headers: HashMap<u64, BlockHeader>,

    /// Total number of slots in the current state space.
    pub num_slots: u64,

    /// Number of live UTXO slots at the current tip.
    pub active_slot_count: u64,

    /// Exact anchor id accepted by user transactions in the next child block.
    pub user_epoch_anchor_id: [u8; 32],

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
        let anchor_height = tx_epoch_anchor_height_for_child(tip_height + 1);
        let user_epoch_anchor_id = recent_headers
            .get(&anchor_height)
            .map(block_id)
            .unwrap_or([0u8; 32]);
        Self {
            tip_height,
            recent_headers,
            num_slots,
            active_slot_count,
            user_epoch_anchor_id,
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
        let mut view = Self::new(
            ctx.tip_height,
            ctx.recent_headers.clone(),
            ctx.state.active_slot_count,
            ctx.state.state.clone(),
        );
        let anchor_height = tx_epoch_anchor_height_for_child(ctx.tip_height + 1);
        view.user_epoch_anchor_id = ctx
            .get_header_from_store(anchor_height)
            .ok()
            .flatten()
            .map(|header| block_id(&header))
            .unwrap_or([0u8; 32]);
        view
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_child_anchor_is_exact_at_143_144_145_boundary() {
        let genesis = noid_chain::consensus::genesis::genesis_header();
        let mut boundary = genesis;
        boundary.height = 144;
        boundary.timestamp = boundary.timestamp.saturating_add(144);
        let genesis_id = block_id(&genesis);
        let boundary_id = block_id(&boundary);
        let headers = HashMap::from([(0, genesis), (144, boundary)]);

        let view = |tip_height| {
            ChainView::new(
                tip_height,
                headers.clone(),
                0,
                noid_chain::state::ChainState::with_log_slots(8).state,
            )
        };
        assert_eq!(view(142).user_epoch_anchor_id, genesis_id); // child 143
        assert_eq!(view(143).user_epoch_anchor_id, genesis_id); // child 144
        assert_eq!(view(144).user_epoch_anchor_id, boundary_id); // child 145
    }
}
