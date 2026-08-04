// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Recursive proof authority for one atomic accepted block.
//!
//! The only protocol carried by this crate is `HistoryStep`: the current
//! block relation and the persisted parent terminal are proved as one unit.

pub mod acceptance;
pub mod accumulator;
pub mod region_sidecar;

pub use acceptance::history_step::{
    decode_history_step_terminal, decode_verify_history_step_terminal,
    derive_history_step_direct_block_vk, derive_history_step_runtime_parts,
    encode_history_step_terminal, freeze_history_step_bank, history_step_terminal_max_wire_bytes,
    pin_history_step_class_bank, prepare_history_step_authorizations, prepare_history_step_for_pow,
    prepare_history_step_ghost_authorization, probe_built_history_step_joint_c1,
    probe_built_history_step_joint_c1_full, prove_built_history_step_terminal, prove_history_step,
    verify_history_step_terminal, AcceptedHistoryStepTerminal, AuthorizationComponentInput,
    BuiltHistoryStep, ExactStateStructuralFrontierInputs, FrozenHistoryStepBank,
    HistoryStepAuthorizationError, HistoryStepBlockComponents, HistoryStepBlockInput,
    HistoryStepError, HistoryStepFreezeError, HistoryStepFreezeInput,
    HistoryStepFreezeInputProvider, HistoryStepFreezeMatrixStore, HistoryStepFreezeStage,
    HistoryStepInputError, HistoryStepMatrixLease, HistoryStepMatrixSource,
    HistoryStepMatrixSourceError, HistoryStepParentTranscriptLayout, HistoryStepRuntime,
    HistoryStepRuntimeParts, HistoryStepSidecarOperation, HistoryStepTerminal,
    JointC1FullProofProbe, JointC1SidecarProbe, PreparedHistoryStepAuthorizations,
    PreparedHistoryStepForPow, PreparedHistoryStepGhostAuthorization,
    HISTORY_STEP_RUNTIME_PARTS_COMPACT_MAX_BYTES, HISTORY_STEP_RUNTIME_PARTS_COMPACT_VERSION,
    HISTORY_STEP_WIRE_VERSION,
};
pub use acceptance::history_step_bank::{
    canonical_history_step_class_id, canonical_history_step_pcs_params,
    canonical_history_step_shape, history_step_bank_io_layout, history_step_bank_io_spec,
    CanonicalHistoryStepClassId, HistoryStepBankEntryPins, HistoryStepBankError,
    HistoryStepBankIoLayout, PinnedHistoryStepBankEntry, PinnedHistoryStepClassBank,
    HISTORY_STEP_CLASS_COUNT, HISTORY_STEP_CURRENT_CLASS_MS, HISTORY_STEP_TIER_SLOT_COUNT,
};
pub use accumulator::{
    genesis_accumulator, ChainAccumulator, ChainAccumulatorAdvanceError, ChainAccumulatorLaneError,
    ChainAccumulatorLocalBoundaryError, CHAIN_ACCUMULATOR_LANES,
};
