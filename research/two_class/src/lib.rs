// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Isolated B64/B255 PagedSpend laboratory.
//!
//! Nothing in this crate is consensus authority. It is intentionally outside
//! the production Cargo workspace. Only tested PagedSpend semantics and the
//! m23/m24 parent-union certificate may move into production.

#[cfg(test)]
mod circuit_support;
pub mod geometry;
pub mod paged_spend;
pub mod parent_union;
