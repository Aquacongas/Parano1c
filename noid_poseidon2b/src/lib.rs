// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid. All rights reserved.

//! Poseidon2b over GF(2^128): native permutation, sponge, and hasher trait.

pub mod batch;
pub mod channel;
pub mod hasher;
pub mod hasher_impl;
pub mod native;

pub use channel::Poseidon2bChannel;
pub use hasher::*;
pub use native::*;
