// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Interleaved column commitment for FRI-Binius PCS.
//!
//! All columns are bound into a single compact cap (2^5 = 32 hashes)
//! via parallel Blake3 segment hashing. No per-column NTT or full
//! Merkle tree is built — the FRI opening proof handles its own
//! commitment of the batched polynomial separately.

use noid_core::{AdditiveNTT, Block128};
use noid_fri::hasher::{CryptographicHasher, HashOutput};
use rayon::prelude::*;

use crate::MERKLE_CAP_DEPTH;

/// Top levels of the commitment kept as a compact binding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleCap {
    pub hashes: Vec<HashOutput>,
}

/// Public commitment to all interleaved columns (sent to verifier).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InterleavedCommitment {
    pub cap: MerkleCap,
    pub log_rows: usize,
    pub n_cols: usize,
}

/// Prover-side state retained after commitment (not sent to verifier).
///
/// M5: `encoded_cols` removed — it was always `Vec::new()` and wasted
/// layout space.  Only `raw_cols` (borrowed references to the actual
/// column data) are kept.
pub struct InterleavedProverState<'a> {
    pub raw_cols: Vec<&'a [Block128]>,
    pub log_rows: usize,
    pub n_cols: usize,
}

/// Commit all columns into a compact cap + prover state.
///
/// Uses parallel Blake3 hashing over column data segments. Each of the
/// 2^CAP_DEPTH segments covers `n / 2^CAP_DEPTH` rows and all columns.
/// This provides collision-resistant binding without NTT or full tree.
pub fn interleaved_commit<'a>(
    cols: &[&'a [Block128]],
    _ntt: &AdditiveNTT<Block128>,
    _hasher: &dyn CryptographicHasher,
) -> (InterleavedCommitment, InterleavedProverState<'a>) {
    assert!(!cols.is_empty());
    let n = cols[0].len();
    assert!(n.is_power_of_two());
    let log_rows = n.trailing_zeros() as usize;
    let n_cols = cols.len();

    for col in cols.iter() {
        assert_eq!(col.len(), n, "All columns must have the same length");
    }

    let cap_size = 1usize << MERKLE_CAP_DEPTH;
    let rows_per_segment = n / cap_size;

    let cap_hashes: Vec<HashOutput> = (0..cap_size)
        .into_par_iter()
        .map(|seg| {
            let start = seg * rows_per_segment;
            let end = start + rows_per_segment;
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"PARANOID/INTERLEAVED-CAP/v1");
            hasher.update(&(seg as u64).to_le_bytes());
            hasher.update(&(n_cols as u64).to_le_bytes());
            hasher.update(&(log_rows as u64).to_le_bytes());
            for row in start..end {
                for col in cols.iter() {
                    let bytes = col[row].0.to_le_bytes();
                    hasher.update(&bytes);
                }
            }
            *hasher.finalize().as_bytes()
        })
        .collect();

    let cap = MerkleCap { hashes: cap_hashes };

    let commitment = InterleavedCommitment {
        cap,
        log_rows,
        n_cols,
    };

    let state = InterleavedProverState {
        raw_cols: cols.to_vec(),
        log_rows,
        n_cols,
    };

    (commitment, state)
}

/// Absorb the cap into a Fiat-Shamir channel.
pub fn absorb_cap(channel: &mut noid_fri::Channel, cap: &MerkleCap) {
    for hash in &cap.hashes {
        let hi = u128::from_le_bytes(hash[..16].try_into().unwrap());
        let lo = u128::from_le_bytes(hash[16..].try_into().unwrap());
        channel.observe_field_elem(Block128::from(hi));
        channel.observe_field_elem(Block128::from(lo));
    }
}

impl InterleavedCommitment {
    pub fn tree_depth(&self) -> usize {
        self.log_rows
    }
}
