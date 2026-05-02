// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Chain layer for Paranoid.
//!
//! Ties transactions (`noid_tx`) to the on-chain state: the FRI-committed
//! UTXO state vector and the block-header hash.
//!
//! Two entry points:
//!
//! - [`hash_block_header`] — canonical `H_BLOCK` with the `BLOCKHDR`
//!   capacity IV. Consumes the seven fields defined in §8.1 in order.
//! - [`apply_tx`] — applies a validated `TxBody` to mutable state,
//!   returning the post-transition state root. This is the native-side
//!   shadow of the state-transition relation that the STARK enforces
//!   in-circuit.

pub mod block;
pub mod block_header;
pub mod da;
pub mod fri_state;
pub mod state;
pub mod wire;

pub use fri_state::{
    eval_point_for_index, verify_opening, FriState, SlotColumnOpening, SlotOpening, SlotValue,
    StateError, StateRoot, STATE_LOG_SLOTS,
};

pub use da::{
    pack_trace, packed_witness_root, payload_bytes, trace_witness_root, unpack_trace, DaError,
    PackedWitness, PackedWitnessColumn,
};

pub use block::{
    apply_block, compute_tx_root, proof_transcript_hash, Block, BlockApplyError, BLOCK_MAX_TXS,
    BLOCK_VERSION,
};
pub use block_header::{hash_block_header, BlockHeader};
pub use state::{apply_tx, ApplyError, ChainState, StateTransition};
pub use wire::BLOCK_HEADER_WIRE_SIZE;
