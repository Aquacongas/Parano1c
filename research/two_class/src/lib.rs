// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Isolated two-class feasibility laboratory.
//!
//! Nothing in this crate is consensus authority. It is intentionally outside
//! the production Cargo workspace. A result may move into production only
//! after the complete B128 m23 and two-shape parent gates in `ROADMAP.md`.

pub mod action_relation;
pub mod authorization;
pub mod budget;
pub mod capsule_leaf_transpose;
pub mod capsule_merkle_forest;
mod circuit_support;
pub mod exact_state_relation;
pub mod geometry;
pub mod group_fee;
pub mod page_binding;
pub mod paged_spend;
pub mod paged_spend_relation;
pub mod partial_candidate;
