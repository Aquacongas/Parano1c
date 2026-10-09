// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Miner-independent release-pinned HistoryStep runtime artifacts.
//!
//! This crate contains only:
//! - pinned runtime metadata codec;
//! - canonical embedded matrix leaf representation;
//! - authenticated matrix runtime source;
//! - cache image handling.
//!
//! It contains no PoW miner, block producer, RPC or GUI code.

mod artifacts;

pub use artifacts::*;
