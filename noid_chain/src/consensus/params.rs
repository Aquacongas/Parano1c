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

/// Maximum transactions per block.
///
/// This is the consensus hard cap. Miner/template policy may choose fewer txs
/// on weaker hardware, but validators accept any block within this cap.
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
/// 2. How far back block headers are retained for anchor validation.
///
/// Note: the window *size* is ANCHOR_DEPTH+1 (inclusive on both ends).
/// The constant name reflects maximum *depth*, not window size.
///
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

/// Consensus hard-finality depth.
///
/// Reorgs that would change the finalized prefix are rejected by fork choice.
/// `18` is suitable only as an initial testnet value (~4.5 minutes at 15s
/// blocks); mainnet must choose this independently in protocol parameters.
pub const CONSENSUS_FINALITY_DEPTH: u64 = 18; // testnet initial value

/// Undo-log retention depth for local shallow reorg recovery.
///
/// This is intentionally separate from consensus finality. Retention may be
/// tuned for operational needs; it must not silently define finality.
pub const UNDO_RETENTION_DEPTH: u64 = 18;

/// Recent full-block retention depth for peer serving.
pub const RECENT_BLOCK_RETENTION_DEPTH: u64 = UNDO_RETENTION_DEPTH;

/// Compatibility alias for older internal callers.
pub const FINALITY_DEPTH: u64 = CONSENSUS_FINALITY_DEPTH;

/// Backwards-compatible alias for in-memory undo pruning.
pub const UNDO_LOG_RETENTION: u64 = UNDO_RETENTION_DEPTH;

/// Number of finalised block headers used for the expansion trigger median.
/// Using median over this window makes the trigger immune to single-block spam.
/// Must be ≤ available recent-header retention.
pub const EXPANSION_WINDOW: u64 = CONSENSUS_FINALITY_DEPTH; // 18 blocks

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

/// Genesis difficulty target = 2^237.
///
/// Calibrated to roughly the same wall-clock genesis solve time as the previous
/// difficulty floor, using production Poseidon2b PoW on the current 12-core laptop:
///   measured parallel Poseidon2b PoW ≈ 186 KH/s
///   avg_nonces = 2^(256-237) = 2^19 = 524,288
///   time = 524K / 186K ≈ 2.8s
///
/// LE 256-bit layout: byte 29 = 0x20 (bit 237 = bit 5 of byte 29).
/// Bytes 30-31 = 0x00 so the target value equals 2^237.
///
/// This is the minimum allowed difficulty floor. ASERT may only move harder.
pub const GENESIS_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[29] = 0x20; // bit 5 of byte 29 -> 2^(8*29+5) = 2^237
    t
};

/// Minimum cumulative PoW work required to accept a state snapshot.
///
/// Stored as LE u256, matching `add_work`/`block_work` layout.
///
/// # Derivation
///
/// Chainwork accounting uses the strict-`< target` expected-trial-count
/// formula:
///   Work(T) = floor((2^256 - 1) / T) + 1.
///
/// For `GENESIS_TARGET = 2^237`, every block contributes:
///   block_work(GENESIS_TARGET) = 2^19 = 524,288
///
/// We require CONSENSUS_FINALITY_DEPTH (18) blocks' worth of work:
///
///   MIN_SNAPSHOT_CHAINWORK = CONSENSUS_FINALITY_DEPTH * block_work(GENESIS_TARGET)
///                          = 18 * 2^19 = 9,437,184 = 0x0090_0000
///
/// # Why CONSENSUS_FINALITY_DEPTH?
///
/// Local history cache updates only cover blocks that are
/// CONSENSUS_FINALITY_DEPTH behind tip. Public arbitrary-peer snapshot sync is
/// still disabled fail-closed until the history proof verifier is authority.
/// The chainwork floor remains a resource/sanity guard for that path:
///
///   tip < 18  -> no finalized history cache and chainwork < threshold
///   tip >= 18 -> local cache may exist, but is not snapshot authority
///
/// # Security vs fake snapshots
///
///   - 155 fake MAX_TARGET blocks (work=2/block) -> chainwork = 310 << 9.4M -> FAILS
///   - 18 real blocks + genesis  -> chainwork >= 18 * 2^19 -> PASSES
pub const MIN_SNAPSHOT_CHAINWORK: [u8; 32] = {
    let mut w = [0u8; 32];
    // 18 * 2^19 = 0x90_0000 = 9,437,184
    // In LE bytes: byte[2] = 0x90.
    w[2] = 0x90; // = CONSENSUS_FINALITY_DEPTH(18) * block_work(GENESIS_TARGET)
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

// ---------------------------------------------------------------------------
// Emission
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
// Fee policy
// ---------------------------------------------------------------------------

/// Base minimum fee in μNOID per non-coinbase transaction.
pub const MIN_FEE_BASE: u64 = 5_000; // 0.005 NOID

/// Small anti-DoS fee charged per live input verified by a transaction.
///
/// Inputs do not grow chain state, so this intentionally stays much lower than
/// the output fee. It keeps very large-input transactions from becoming free
/// relay/prover spam without penalising useful sweep/consolidation shapes.
pub const FEE_PER_INPUT: u64 = 100; // 0.0001 NOID per input

/// Fee charged per live output created by a transaction.
///
/// Outputs are the main user-visible driver of fee because they create UTXOs and
/// may increase state pressure. The 1-input/2-output low-pressure send remains
/// at the historical 9_000 μNOID baseline together with state-growth burn.
pub const FEE_PER_OUTPUT: u64 = 700; // 0.0007 NOID per output

/// Base fee charged per net-new live UTXO slot at low occupancy.
/// This state-growth component is burned by consensus.
pub const STATE_GROWTH_FEE_BASE: u64 = 2_500; // 0.0025 NOID per net-new slot

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_target_is_2_pow_237() {
        // 2^237: bit 237 = bit 5 of byte 29 (LE). Bytes 30-31 = 0x00.
        let mut expected = [0u8; 32];
        expected[29] = 0x20; // 2^5 at byte 29 -> 2^(8*29+5) = 2^237
        assert_eq!(GENESIS_TARGET, expected);
        assert_eq!(GENESIS_TARGET[28], 0x00);
        assert_eq!(GENESIS_TARGET[29], 0x20);
        assert_eq!(GENESIS_TARGET[30], 0x00);
        assert_eq!(GENESIS_TARGET[31], 0x00);
    }

    #[test]
    fn epoch_timing_is_consistent() {
        assert_eq!(HALFLIFE, EPOCH_LENGTH * BLOCK_TIME);
        assert_eq!(HALFLIFE, 90, "HALFLIFE = 6 epochs × 15s");
        assert_eq!(CONSENSUS_FINALITY_DEPTH, 3 * EPOCH_LENGTH);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn emission_floor_positive() {
        assert!(FLOOR_REWARD_MICRONOID > 0);
        assert!(BASE_REWARD_MICRONOID > FLOOR_REWARD_MICRONOID);
        assert_eq!(BASE_REWARD_MICRONOID, 50 * MICRONOID_PER_NOID);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn log_slots_range() {
        assert!(LOG_SLOTS_GENESIS < LOG_SLOTS_MAX);
        assert_eq!(LOG_SLOTS_GENESIS, 24);
        assert_eq!(LOG_SLOTS_MAX, 32);
        // Each segment fits in 2^16 slots, genesis has 2^(24-16)=256 segments
        assert_eq!(1u32 << (LOG_SLOTS_GENESIS - LOG_SEGMENT_SIZE), 256);
    }
}
