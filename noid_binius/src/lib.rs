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
//! For the **Byte** and **Block128** domains, FRI opens the packed MLE
//! directly — the packed vector *is* the polynomial the AIR reasons about.
//! For the **Bit** domain, the packed commitment is canonical for DA and
//! for the Merkle root on chain; inside prove/verify the column is expanded
//! back to Block128 and opened via the standard FRI PCS.

pub mod commit;
pub mod pack;
pub mod witness;

pub use commit::{PackedCommit, PackedCommitment, PackedEvalProof};
pub use pack::{unpack_bits, unpack_bytes, pack_bits, pack_bytes, BETA};
pub use witness::{BitWitness, ByteWitness};
