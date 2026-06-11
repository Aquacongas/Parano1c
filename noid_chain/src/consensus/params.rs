// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! All consensus constants.

/// Target inter-block interval in seconds.
///
/// ASERT adjusts PoW difficulty so all hardware converges to this target.
/// Bounded below by `prove_block_time` on the miner's hardware; PoW is
/// ordering-only, not security-critical.
pub const BLOCK_TIME: u64 = 15;

/// Number of blocks per ASERT epoch.
pub const EPOCH_LENGTH: u64 = 6;

/// ASERT halflife in seconds = EPOCH_LENGTH × BLOCK_TIME.
pub const HALFLIFE: u64 = EPOCH_LENGTH * BLOCK_TIME; // 90s at BLOCK_TIME=15

/// Maximum seconds a block timestamp may exceed local wall clock.
pub const MAX_FUTURE_DRIFT: u64 = 120;

/// Number of previous blocks used for median-time-past.
pub const MEDIAN_TIME_BLOCKS: usize = 11;

// ---------------------------------------------------------------------------
// Block limits
// ---------------------------------------------------------------------------

/// Maximum non-coinbase transactions per block.
///
/// Hardware is the natural regulator: weak nodes prove fewer txs within
/// BLOCK_TIME and fall back to coinbase-only blocks via the prove semaphore.
/// A 32-core server can prove ~256 txs in ~15s; a laptop proves ~130 txs
/// within BLOCK_TIME. ASERT adjusts so average block time converges regardless.
pub const BLOCK_MAX_TXS: usize = 256;

/// Maximum inputs per transaction.
pub const MAX_INPUTS: usize = 4;

/// Maximum outputs per transaction.
pub const MAX_OUTPUTS: usize = 8;

// ---------------------------------------------------------------------------
// Epoch anchor
// ---------------------------------------------------------------------------

/// Epoch anchor validity depth.
///
/// A non-coinbase tx's epoch_anchor must reference a header at height in
/// `[block_height - ANCHOR_DEPTH - 1, block_height - 1]`.
/// This gives a window of **ANCHOR_DEPTH + 1 = 145** possible anchor heights.
///
/// At 15 s block time: ~36 minutes under normal conditions.
///
/// Controls:
/// 1. How old a transaction's epoch_anchor may be (wallet tx validity window).
/// 2. How long nullifiers are retained (prevents double-spend within window).
///
/// Note: the window *size* is ANCHOR_DEPTH+1 (inclusive on both ends).
/// The constant name reflects maximum *depth*, not window size.
///
/// NullifierSet max RAM: 144 blocks × 256 txs × 32 bytes = ~1.2 MB (negligible).
pub const ANCHOR_DEPTH: u64 = 144;

// Compile-time assertion: ANCHOR_DEPTH must match noid_tx::ANCHOR_DEPTH.
// If they drift, replay protection breaks.
const _: () = assert!(
    ANCHOR_DEPTH == noid_tx::ANCHOR_DEPTH,
    "noid_chain ANCHOR_DEPTH must equal noid_tx::ANCHOR_DEPTH"
);

// ---------------------------------------------------------------------------
// Finality
// ---------------------------------------------------------------------------

/// After this many confirmations a block is considered final.
/// Reorgs deeper than this are rejected by fork choice.
pub const FINALITY_DEPTH: u64 = 18; // 3 × EPOCH_LENGTH

/// Number of finalised block headers used for the expansion trigger median.
/// Using median over this window makes the trigger immune to single-block spam.
/// Must be ≤ FINALITY_DEPTH so the required headers are always available as undo logs.
pub const EXPANSION_WINDOW: u64 = FINALITY_DEPTH; // 18 blocks

// ---------------------------------------------------------------------------
// Slot state
// ---------------------------------------------------------------------------

/// Initial `log_slots` at genesis: 2^24 = 16,777,216 slots.
pub const LOG_SLOTS_GENESIS: u32 = 24;

/// Maximum `log_slots`: 2^32 = 4,294,967,296 slots.
pub const LOG_SLOTS_MAX: u32 = 32;

/// Each segment holds 2^LOG_SEGMENT_SIZE slots.
pub const LOG_SEGMENT_SIZE: u32 = 16;

/// Fraction of current capacity that triggers expansion (numerator/denominator).
/// When `active_slot_count * EXPAND_DENOM >= 2^log_slots * EXPAND_NUM`, expand.
pub const EXPAND_NUM: u64 = 3; // 75 %
pub const EXPAND_DENOM: u64 = 4;

// ---------------------------------------------------------------------------
// PoW
// ---------------------------------------------------------------------------

/// Genesis difficulty target = 2^229.
///
/// Calibrated to ~2 seconds per block on a 12-core laptop (62 MH/s total):
///   avg_nonces = 2^(256-229) = 2^27 = 134M
///   time = 134M / 62M ≈ 2.2s
///
/// LE 256-bit layout: byte 28 = 0x20 (bit 229 = bit 5 of byte 28).
/// Bytes 29-31 = 0x00 so the target value equals 2^229.
///
/// This is the minimum allowed difficulty floor. ASERT may only move harder.
pub const GENESIS_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[28] = 0x20; // bit 5 of byte 28 → 2^(8×28+5) = 2^229
    t
};

/// Minimum cumulative PoW work required to accept a state snapshot.
///
/// Stored as LE u128 in bytes [0..16], matching `add_work`/`block_work` layout.
///
/// # Derivation
///
/// The difficulty floor ensures every block contributes at least:
///   block_work(GENESIS_TARGET) = 2^26 = 67,108,864  (26 leading zeros)
///
/// We require FINALITY_DEPTH (18) blocks' worth of work:
///
///   MIN_SNAPSHOT_CHAINWORK = FINALITY_DEPTH × block_work(GENESIS_TARGET)
///                          = 18 × 2^26 = 1,207,959,552 = 0x4800_0000
///
/// # Why FINALITY_DEPTH?
///
/// The recursive proof updater only builds proofs for blocks that are
/// FINALITY_DEPTH behind tip. Until a peer has 18+ finalized blocks it has
/// NO recursive proof. Requiring 18 blocks of chainwork aligns these two:
///
///   tip < 18  → no recursive proof AND chainwork < threshold → peer cannot serve sync
///   tip ≥ 18  → recursive proof exists AND chainwork ≥ threshold → peer can serve sync
///
/// # Security vs fake snapshots
///
///   • 155 fake MAX_TARGET blocks (work=1/block) → chainwork = 155 ≪ 1.2B → FAILS
///   • 18 real blocks + genesis  → chainwork ≥ 18 × 2^26 → PASSES
pub const MIN_SNAPSHOT_CHAINWORK: [u8; 32] = {
    let mut w = [0u8; 32];
    // 18 × 2^26 = 0x12 × 0x400_0000 = 0x4800_0000 = 1,207,959,552
    // In LE bytes: byte[3] = 0x48 (bits 24-31)
    // Verify: 0x48 × 2^24 = 72 × 16,777,216 = 1,207,959,552 = 18 × 67,108,864 ✓
    w[3] = 0x48; // = FINALITY_DEPTH(18) × block_work(GENESIS_TARGET)
    w
};

/// Minimum allowed target (maximum difficulty). Theoretical floor.
pub const MIN_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[0] = 1;
    t
};

/// Maximum allowed target (minimum difficulty = trivially satisfied).
pub const MAX_TARGET: [u8; 32] = [0xFF; 32];

// ---------------------------------------------------------------------------
// DA retention
// ---------------------------------------------------------------------------

/// How many blocks to keep for undo logs (local reorg) AND for serving to peers
/// (shallow fork resolution).
///
/// Both needs are identical: you can only reorg up to FINALITY_DEPTH blocks,
/// and peers only need blocks within that window (deeper forks use O(1) snapshot
/// sync instead). A single constant avoids the confusion of two separate values.
pub const UNDO_LOG_RETENTION: u64 = FINALITY_DEPTH;

// ---------------------------------------------------------------------------
// Emission  (ROADMAP2.md §Emission)
// ---------------------------------------------------------------------------

/// Precision: 1 NOID = 1_000_000 μNOID (microNOID).
pub const MICRONOID_PER_NOID: u64 = 1_000_000;

/// Starting block reward at zero occupancy: 50 NOID.
pub const BASE_REWARD_MICRONOID: u64 = 50 * MICRONOID_PER_NOID;

/// Reward floor: 1 NOID forever.
pub const FLOOR_REWARD_MICRONOID: u64 = MICRONOID_PER_NOID;

// ---------------------------------------------------------------------------
// Slot allocator PRNG
// ---------------------------------------------------------------------------
// splitmix64 constants are embedded in noid_chain::consensus::allocator.
// No separate params needed — the algorithm uses fixed Weyl/mixing constants.

// ---------------------------------------------------------------------------
// Fee policy  (non-consensus — local node enforcement only)
// ---------------------------------------------------------------------------

/// Minimum relay fee in μNOID per transaction (covers amortized proving cost).
/// Nodes MAY raise this; they MUST NOT relay below this default.
pub const MIN_FEE_BASE: u64 = 5_000; // 0.005 NOID

/// Additional relay fee per valid output slot (covers permanent state cost).
pub const FEE_PER_OUTPUT: u64 = 2_000; // 0.002 NOID per output

/// Compute the minimum acceptable fee for a tx with `n_outputs` valid outputs.
pub const fn min_fee(n_outputs: u64) -> u64 {
    MIN_FEE_BASE + n_outputs * FEE_PER_OUTPUT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_target_is_2_pow_229() {
        // 2^229: bit 229 = bit 5 of byte 28 (LE). Bytes 29-31 = 0x00.
        let mut expected = [0u8; 32];
        expected[28] = 0x20; // 2^5 at byte 28 → 2^(8*28+5) = 2^229
        assert_eq!(GENESIS_TARGET, expected);
        assert_eq!(GENESIS_TARGET[28], 0x20);
        assert_eq!(GENESIS_TARGET[29], 0x00);
        assert_eq!(GENESIS_TARGET[30], 0x00);
        assert_eq!(GENESIS_TARGET[31], 0x00);
    }

    #[test]
    fn epoch_timing_is_consistent() {
        assert_eq!(HALFLIFE, EPOCH_LENGTH * BLOCK_TIME);
        assert_eq!(HALFLIFE, 90, "HALFLIFE = 6 epochs × 15s");
        assert_eq!(FINALITY_DEPTH, 3 * EPOCH_LENGTH);
    }

    #[test]
    fn emission_floor_positive() {
        assert!(FLOOR_REWARD_MICRONOID > 0);
        assert!(BASE_REWARD_MICRONOID > FLOOR_REWARD_MICRONOID);
        assert_eq!(BASE_REWARD_MICRONOID, 50 * MICRONOID_PER_NOID);
    }

    #[test]
    fn min_fee_formula() {
        assert_eq!(min_fee(0), MIN_FEE_BASE);
        assert_eq!(min_fee(1), MIN_FEE_BASE + FEE_PER_OUTPUT);
        assert_eq!(min_fee(8), MIN_FEE_BASE + 8 * FEE_PER_OUTPUT);
        // Ensure non-zero floor even with zero outputs (coinbase).
        assert!(min_fee(0) > 0);
    }

    #[test]
    fn log_slots_range() {
        assert!(LOG_SLOTS_GENESIS < LOG_SLOTS_MAX);
        assert_eq!(LOG_SLOTS_GENESIS, 24);
        assert_eq!(LOG_SLOTS_MAX, 32);
        // Each segment fits in 2^16 slots, genesis has 2^(24-16)=256 segments
        assert_eq!(1u32 << (LOG_SLOTS_GENESIS - LOG_SEGMENT_SIZE), 256);
    }
}
