// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Chain layer for Paranoid.
//!
//! Ties transactions (`noid_tx`) to the on-chain state: the segmented
//! FRI-committed UTXO state vector and the block-header hash.
//!
//! Two primary entry points:
//!
//! - [`hash_block_header`] — canonical `H_BLOCK` with the `BLOCKHDR`
//!   capacity IV.
//! - [`apply_tx`] — applies a validated `TxBody` to mutable state,
//!   returning the post-transition state root. Native-side shadow of the
//!   state-transition relation that the STARK enforces in-circuit.

pub mod block;
pub mod block_header;
pub mod chain_context;
pub mod consensus;
pub mod da;
pub mod fri_state;
pub mod mempool;
pub mod nullifier;
pub mod segmented_state;
pub mod state;
pub mod state_binding;
pub mod state_delta;
pub mod storage;
pub mod wire;

// ---------------------------------------------------------------------------
// FRI state primitives (per-segment level)
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
    zero_segment_root_16, zero_segtree_node, SegmentColumns, SegmentedFriState, MAX_SEGTREE_DEPTH,
    SEGMENT_SIZE,
};

// ---------------------------------------------------------------------------
// Storage backends
// ---------------------------------------------------------------------------

pub use storage::{
    MdbxChainContext, MdbxContextError, MdbxStore, RamBackend, StateBackend, StoreError,
};

// ---------------------------------------------------------------------------
// DA layer
// ---------------------------------------------------------------------------

pub use da::{
    pack_trace, packed_witness_root, payload_bytes, trace_witness_root, unpack_trace, DaError,
    PackedWitness, PackedWitnessColumn,
};

// ---------------------------------------------------------------------------
// Block layer
// ---------------------------------------------------------------------------

pub use block::{
    apply_block, apply_genesis_block, apply_state_delta, compute_tx_root, proof_transcript_hash,
    validate_block_proof_binding, Block, BlockApplyError, ProofBindingError, BLOCK_MAX_TXS,
    STUB_PROOF_MARKER,
};
pub use block_header::{hash_block_header, BlockHeader};

// ---------------------------------------------------------------------------
// Chain state
// ---------------------------------------------------------------------------

pub use chain_context::ChainContext;
pub use mempool::{Mempool, MempoolEntry, MempoolError};
pub use nullifier::NullifierSet;
pub use state::{apply_tx, ApplyError, ChainState, StateTransition};
pub use state_binding::{BlockStateBinding, StateBindingError, TxStateOpening};
pub use state_delta::{
    build_state_delta_action_surface, build_state_delta_witness, StateDeltaAction,
    StateDeltaActionKind, StateDeltaActionSurface, StateDeltaError, StateDeltaWitness,
};
pub use wire::BLOCK_HEADER_WIRE_SIZE;

// ---------------------------------------------------------------------------
// Chainwork primitives (re-exported for external crates)
// ---------------------------------------------------------------------------

pub use consensus::difficulty::{add_work, block_work, work_gt};
pub use consensus::fork_choice::choose_chain_by_work;
