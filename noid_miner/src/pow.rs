// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Parallel Blake3 PoW nonce search.
//!
//! PoW is computed over `header_core` (212 bytes, excludes `proof_transcript_hash`).
//! This allows ZK proving and PoW search to run concurrently.
//!

use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::difficulty::le256_lt;
use noid_chain::consensus::pow::{header_core_bytes_into, NONCE_OFFSET};

/// Result of a successful PoW search.
#[derive(Debug, Clone)]
pub struct PowSolution {
    pub nonce: u128,
    pub pow_hash: [u8; 32],
}

/// Search for a valid PoW nonce using all available CPU threads (rayon).
///
/// `header_template` must have `proof_transcript_hash = [0;32]` and `witness_root = [0;32]`
/// (they are not part of the PoW hash; only `header_core` is hashed).
///
/// Returns `Some(PowSolution)` when found, or `None` if cancelled via the
/// `cancel` channel (when a new P2P block arrives or a new template is ready).
pub fn search_pow_parallel(
    header_template: &BlockHeader,
    cancel: &std::sync::atomic::AtomicBool,
) -> Option<PowSolution> {
    use rayon::prelude::*;
    use std::sync::atomic::Ordering;

    // Start from a random nonce to avoid all miners/restarts colliding on nonce=0.
    // Uses a simple time-based seed — not cryptographic, just for nonce diversity.
    let random_start: u128 = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u128;
        // Mix with block height for additional diversity.
        (t ^ (header_template.height as u128).wrapping_mul(0x9E3779B97F4A7C15))
            & 0xFFFF_FFFF_FFFF_FFFF // 64-bit random start
    };

    // Partition the 128-bit nonce space into thread-sized chunks.
    // Each thread checks cancel every per_thread iterations (~125K on 8 cores).
    // At ~1M hashes/s/core this gives ~125ms cancel latency.
    const CHUNK_SIZE: u128 = 1_000_000;
    let target = header_template.difficulty_target;

    let mut start_nonce: u128 = random_start;

    // Hoist thread count — it never changes during a chunk.
    let num_threads = rayon::current_num_threads();
    let per_thread = CHUNK_SIZE / num_threads as u128;

    loop {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }

        // Search this chunk in parallel. Each thread gets a stack buffer
        // (no heap allocation), patches only the 16 nonce bytes per iteration.
        let solution: Option<PowSolution> =
            (0..num_threads).into_par_iter().find_map_any(|thread_id| {
                let thread_start = start_nonce + (thread_id as u128) * per_thread;
                let thread_end = thread_start + per_thread;

                let mut buf = [0u8; 212];
                header_core_bytes_into(header_template, &mut buf);

                for nonce in thread_start..thread_end {
                    if cancel.load(Ordering::Relaxed) {
                        return None;
                    }
                    buf[NONCE_OFFSET..NONCE_OFFSET + 16].copy_from_slice(&nonce.to_le_bytes());
                    let hash = *blake3::hash(&buf).as_bytes();
                    if le256_lt(&hash, &target) {
                        return Some(PowSolution {
                            nonce,
                            pow_hash: hash,
                        });
                    }
                }
                None
            });

        if solution.is_some() {
            return solution;
        }

        // Check cancellation before next chunk.
        if cancel.load(Ordering::Relaxed) {
            return None;
        }

        // Advance to the next chunk.
        start_nonce = start_nonce.saturating_add(CHUNK_SIZE);
        if start_nonce == 0 {
            // Nonce space exhausted (extremely unlikely with 128-bit nonce).
            return None;
        }
    }
}
