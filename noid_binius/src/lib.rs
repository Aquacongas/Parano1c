// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid. All rights reserved.

//! Binius-style small-field packing for DA / bandwidth reduction.
//!
//! # What this crate is
//!
//! A packing layer that lets the chain commit and transmit witnesses that are
//! semantically defined over small subfields of GF(2^128) — individual bits
//! (GF(2)) or bytes (GF(2^8)) — while the commitment itself still runs on the
//! existing Block128 (GF(2^128)) FRI PCS.
//!
//! Concretely:
//!
//! * A length-`N` bit witness is stored as `N/128` Block128 words. The DA
//!   payload, the trace size, the FRI Merkle leaf count, and the NTT input
//!   all shrink by 128x.
//! * A length-`N` byte witness (GF(2^8)) shrinks by 16x.
//!
//! This is the same representation Binius / Ulvetanna use at the packing
//! layer. It targets three of the benchmark columns directly:
//!
//! ```text
//!   log_n = 20 (1M cells, Block128 payload) : trace 16 MiB, commit 171 ms
//!   log_n = 20 (1M bits,  bit-packed)       : trace 128 KiB, commit ~1-2 ms
//! ```
//!
//! # What this crate is NOT (yet)
//!
//! It does **not** implement the full Binius ring-switching PCS opening for
//! the *bit*-MLE. That protocol requires a careful sumcheck-plus-row-reveal
//! construction whose soundness argument depends on very specific challenge
//! ordering and basis choices. Shipping it half-right would be worse than
//! not shipping it. Until the full spec + proofs land, users open the
//! *packed* MLE (which FRI already makes sound), and any bit-level identity
//! that cannot be expressed over the packed MLE must go through the
//! non-compressing code path.
//!
//! # Use cases enabled today
//!
//! * Block DA payload: publish packed witnesses; every full node reconstructs
//!   the expanded vector locally before running FRI verification.
//! * State-tree / nullifier-tree leaves that are bit strings: pack them.
//! * Any AIR column whose cells are bits/bytes: commit the packed column and
//!   add bit-decomposition constraints in-circuit (standard AIR technique).

pub mod commit;
pub mod pack;
pub mod witness;

pub use commit::{PackedCommit, PackedCommitment, PackedEvalProof};
pub use pack::{unpack_bits, unpack_bytes, pack_bits, pack_bytes, BETA};
pub use witness::{BitWitness, ByteWitness};
