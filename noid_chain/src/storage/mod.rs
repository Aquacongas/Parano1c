// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! State storage backend abstraction (Phase 3 / F.0).
//!
//! `StateBackend` decouples the chain state from its physical storage.
//! The RAM backend (`SegmentedFriState`) is the default and is used
//! whenever `log_slots ≤ 26`. A future MDBX disk backend will implement
//! the same trait with zero-copy mmap reads (`SegmentView<'txn>`).
//!
//! **K.3 future requirement**: the MDBX backend MUST return zero-copy slices
//! via `load_segment_view<'txn>(...) -> &'txn [Block128]` — NOT `Vec<Block128>`
//! — to avoid memcpy bandwidth collapse at log_slots ≥ 28.

pub mod memory;

pub use memory::RamBackend;

use crate::fri_state::{SlotValue, StateRoot};
use crate::segmented_state::SegmentColumns;

/// Slot storage abstraction.
///
/// Implementations must be byte-identical for `root()`: two backends
/// initialised from the same sequence of `set_slot` calls MUST produce
/// the same `StateRoot`.
pub trait StateBackend {
    /// Read the value at `(seg_id, local_idx)`.
    fn get_slot(&self, seg_id: u16, local_idx: u16) -> SlotValue;

    /// Write the value at `(seg_id, local_idx)`.
    fn set_slot(&mut self, seg_id: u16, local_idx: u16, v: SlotValue);

    /// Load all three column vectors for segment `seg_id`.
    ///
    /// For virtual zero segments, returns all-zero columns without allocating
    /// (via static zero buffer or equivalent).
    fn load_segment_columns(&mut self, seg_id: u16) -> &SegmentColumns;

    /// Flush pending writes to durable storage (no-op for RAM backend).
    fn flush(&mut self);

    /// Compute (or return cached) global state root.
    fn state_root(&mut self) -> StateRoot;
}
