// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Chain layer for Paranoid.
//!
//! Ties transactions (`noid_tx`) to the on-chain state: the segmented raw UTXO
//! vector, exact state commitments, and block-header hash.
//!
//! Two primary entry points:
//!
//! - [`hash_block_header`] — canonical `H_BLOCK` with the `BLOCKHDR`
//!   capacity IV.
//! - [`apply_tx`] — applies one `TxBody` to mutable raw state. User block
//!   acceptance additionally verifies and commits an exact authenticated
//!   state transition.

pub mod block;
pub mod block_header;
pub mod chain_context;
pub mod checkpoint;
pub mod consensus;
pub mod exact_state_hash;
pub mod fri_state;
pub mod header_anchor;
pub mod mempool;
pub mod segmented_state;
pub mod sparse_merkle;
pub mod state;
pub mod state_delta;
pub mod storage;
pub mod tx_tree;
pub mod wire;

// ---------------------------------------------------------------------------
// Raw state primitives (per-segment level)
// ---------------------------------------------------------------------------

pub use fri_state::{
    cap_to_seg_root, eval_point_for_index, eval_point_for_local_index, merkle_root_from_leaf,
    open_segment_at_point, verify_opening, FriState, SlotOpening, SlotValue, StateError, StateRoot,
    LOG_SEGMENT_SIZE, STATE_LOG_SLOTS,
};

// ---------------------------------------------------------------------------
// Segmented state
// ---------------------------------------------------------------------------

pub use segmented_state::{
    zero_segment_root_16, zero_segtree_node, SegmentColumns, SegmentedFriState, StateResizeError,
    MAX_SEGTREE_DEPTH, SEGMENT_SIZE,
};

// ---------------------------------------------------------------------------
// Storage backends
// ---------------------------------------------------------------------------

pub use storage::{
    reconstruct_historical_exact_state, AcceptedBlockCommitData, AppliedBlockValidation,
    CanonicalTipBinding, ClaimedRecursiveProofJobInputs, ConsensusMeta, FinalizedCheckpoint,
    HistoricalExactStateView, HistoricalStateError, MdbxChainContext, MdbxContextError, MdbxStore,
    RamBackend, ReorgBlockPayload, StateBackend, StoreError,
};

// ---------------------------------------------------------------------------
// Block layer
// ---------------------------------------------------------------------------

pub use block::{
    apply_genesis_block, canonical_block_wire_len, compute_tx_root, validate_block_proof_binding,
    Block, BlockApplyError, ProofBindingError, BLOCK_MAX_TXS, BLOCK_WIRE_FIXED_OVERHEAD,
    BLOCK_WIRE_HEADER_OFFSET, BLOCK_WIRE_MARKER, BLOCK_WIRE_NONCE_OFFSET,
};
pub use block_header::{block_id, hash_block_header, BlockHeader};
pub use header_anchor::{
    compute_header_chain_anchor, extend_header_chain_anchor, HeaderChainAnchor,
    HeaderChainAnchorError,
};

// ---------------------------------------------------------------------------
// Checkpoint packages
// ---------------------------------------------------------------------------

pub use checkpoint::{
    CheckpointCoverage, CheckpointSegmentPayload, ImmutableCheckpointManifest,
    ImmutableCheckpointPackage,
};

// ---------------------------------------------------------------------------
// Chain state
// ---------------------------------------------------------------------------

pub use chain_context::ChainContext;
pub use mempool::{Mempool, MempoolEntry, MempoolError};
pub use state::{apply_tx, ApplyError, ChainState, SparseUtxoBuildError, StateTransition};
pub use state_delta::{
    build_exact_action_surface, build_exact_action_surface_at_log_slots,
    build_state_delta_action_surface, build_state_delta_witness, ExactActionSurface,
    StateDeltaAction, StateDeltaActionKind, StateDeltaActionSurface, StateDeltaError,
    StateDeltaWitness,
};
pub use wire::BLOCK_HEADER_WIRE_SIZE;

// ---------------------------------------------------------------------------
// Chainwork primitives (re-exported for external crates)
// ---------------------------------------------------------------------------

pub use consensus::difficulty::{add_work, block_work, work_gt};
pub use consensus::fork_choice::choose_chain_by_work;
