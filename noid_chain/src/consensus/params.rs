// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! All consensus constants. Every constant references SPECIFICATION.md §§.
//! This is the single source of truth — no other file should hardcode these.

// ---------------------------------------------------------------------------
// Timing  (SPECIFICATION.md §18)
// ---------------------------------------------------------------------------

/// Target inter-block interval in seconds (SPECIFICATION.md §18.1).
pub const BLOCK_TIME: u64 = 60;

/// Number of blocks per ASERT epoch (SPECIFICATION.md §18.3.1).
pub const EPOCH_LENGTH: u64 = 6;

/// ASERT halflife in seconds = EPOCH_LENGTH × BLOCK_TIME (SPECIFICATION.md §18.3.1).
pub const HALFLIFE: u64 = EPOCH_LENGTH * BLOCK_TIME; // 360

/// Maximum seconds a block timestamp may exceed local wall clock (SPECIFICATION.md §18.4).
pub const MAX_FUTURE_DRIFT: u64 = 120;

/// Number of previous blocks used for median-time-past (SPECIFICATION.md §18.4).
pub const MEDIAN_TIME_BLOCKS: usize = 11;

// ---------------------------------------------------------------------------
// Block limits  (SPECIFICATION.md §7)
// ---------------------------------------------------------------------------

/// Maximum number of non-coinbase transactions per block.
pub const BLOCK_MAX_TXS: usize = 1024;

/// Maximum inputs per transaction (SPECIFICATION.md §3).
pub const MAX_INPUTS: usize = 4;

/// Maximum outputs per transaction (SPECIFICATION.md §3).
pub const MAX_OUTPUTS: usize = 8;

// ---------------------------------------------------------------------------
// Epoch anchor  (SPECIFICATION.md §2 / §17)
// ---------------------------------------------------------------------------

/// Epoch anchor validity depth.
///
/// A non-coinbase tx's epoch_anchor must reference a header at height in
/// `[block_height - ANCHOR_DEPTH - 1, block_height - 1]`.
/// This gives a window of **ANCHOR_DEPTH + 1 = 145** possible anchor heights.
///
/// At 60s block time: ~144 minutes under normal conditions.
///
/// Controls:
/// 1. How old a transaction's epoch_anchor may be (wallet tx validity window).
/// 2. How long nullifiers are retained (prevents double-spend within window).
///
/// Note: the window *size* is ANCHOR_DEPTH+1 (inclusive on both ends).
/// The constant name reflects maximum *depth*, not window size.
///
/// NullifierSet max RAM: 144 blocks × 1024 txs × 32 bytes = ~4.7 MB (negligible).
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
// Slot state  (SPECIFICATION.md §0 / §15)
// ---------------------------------------------------------------------------

/// Initial `log_slots` at genesis: 2^24 = 16,777,216 slots.
pub const LOG_SLOTS_GENESIS: u32 = 24;

/// Maximum `log_slots`: 2^32 = 4,294,967,296 slots.
pub const LOG_SLOTS_MAX: u32 = 32;

/// Each segment holds 2^LOG_SEGMENT_SIZE slots (SPECIFICATION.md §19).
pub const LOG_SEGMENT_SIZE: u32 = 16;

/// Fraction of current capacity that triggers expansion (numerator/denominator).
/// When `active_slot_count * EXPAND_DENOM >= 2^log_slots * EXPAND_NUM`, expand.
pub const EXPAND_NUM: u64 = 3; // 75 %
pub const EXPAND_DENOM: u64 = 4;

// ---------------------------------------------------------------------------
// PoW  (SPECIFICATION.md §18)
// ---------------------------------------------------------------------------

/// Genesis difficulty target = 2^252. Intentionally trivial so the first
/// miner can bootstrap the chain in microseconds (SPECIFICATION.md §18.5).
pub const GENESIS_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    // 2^252 in little-endian: byte 31 = 0x10 (bit 252 = bit 4 of byte 31)
    t[31] = 0x10;
    t
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
// DA retention  (SPECIFICATION.md §20)
// ---------------------------------------------------------------------------

/// Compact undo logs kept for FINALITY_DEPTH blocks so reorgs can always
/// be reverted. Must equal FINALITY_DEPTH; smaller values would leave
/// deep reorgs unrevertable.
pub const UNDO_LOG_RETENTION: u64 = FINALITY_DEPTH; // 18 blocks

/// `recent_blocks` (kept for P2P sync of lagging peers) pruned after this depth.
pub const RECENT_BLOCK_RETENTION: u64 = FINALITY_DEPTH; // 18 blocks

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
// Slot allocator PRNG  (SPECIFICATION.md §15.1)
// ---------------------------------------------------------------------------
// splitmix64 constants are embedded in noid_chain::consensus::allocator.
// No separate params needed — the algorithm uses fixed Weyl/mixing constants.

// ---------------------------------------------------------------------------
// Pre-proving channel tag  (ROADMAP2.md §Phase 1.5)
// ---------------------------------------------------------------------------

/// Domain tag for the per-tx pre-proving channel (Phase 1.5 / Phase 3).
///
/// Pre-proving: on mempool admission, spawn background `prove_air_algebraic_pretx`
/// keyed by `H(tx_body_hash || PRETX_CHANNEL_TAG)`. Independent of prev_state_root
/// or cap — proofs survive across blocks as long as the tx_body_hash is unchanged.
///
/// Implementation deferred to Phase 3 (requires async tokio mempool).
pub const PRETX_CHANNEL_TAG: &[u8] = b"paranoid-pretx-v1";

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
    fn genesis_target_is_2_pow_252() {
        // 2^252: bit 252 = bit 4 of byte 31 (LE). Bytes 0..30 are zero.
        let mut expected = [0u8; 32];
        expected[31] = 0x10; // 2^4 = 16, placed at byte 31 → value = 16 × 2^(8×31) = 2^252
        assert_eq!(GENESIS_TARGET, expected);
        // Sanity: as LE 256-bit integers, MIN_TARGET(=1) < GENESIS_TARGET(=2^252) < MAX_TARGET(=2^256-1)
        // LE comparison: compare from byte 31 (MSB) down.
        // MIN_TARGET  = [1,0,0,...,0]       byte31=0  → smallest
        // GENESIS_TARGET = [0,...,0,0x10]  byte31=0x10
        // MAX_TARGET  = [0xFF,...,0xFF]     byte31=0xFF → largest
        // Byte 31: MIN(0) < GENESIS(0x10) < MAX(0xFF) ✓
        assert_eq!(GENESIS_TARGET[31], 0x10);
        assert!(GENESIS_TARGET[31] > MIN_TARGET[31], "genesis > min in MSB");
        assert!(GENESIS_TARGET[31] < MAX_TARGET[31], "genesis < max in MSB");
    }

    #[test]
    fn epoch_timing_is_consistent() {
        assert_eq!(HALFLIFE, EPOCH_LENGTH * BLOCK_TIME);
        assert_eq!(HALFLIFE, 360);
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
