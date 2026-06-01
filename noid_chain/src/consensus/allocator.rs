// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Native slot allocator for wallet hint generation (SPECIFICATION.md §15.1).
//!
//! Uses splitmix64 seeded from `alloc_counter` to produce candidate free slot
//! indices. Hints are **non-authoritative** — miners verify slot emptiness via
//! BlockStateBinding. Two wallets may receive the same hint; conflicts are
//! resolved at block inclusion time.
//!
//! splitmix64 is chosen over LCG because it is bijective and all output bits
//! are equally well-distributed. With `idx = splitmix64(counter) mod 2^k`,
//! even the low-order bits (used for slot masking) are fully mixed.
//! Reference: https://prng.di.unimi.it/splitmix64.c

/// splitmix64 — standard 64-bit non-cryptographic bijective mixer.
///
/// State advances by the Weyl sequence constant 0x9e3779b97f4a7c15;
/// the output is mixed through two multiply-xorshift rounds.
/// Every input maps to a unique output (bijection over u64).
#[inline]
pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Generate `count` candidate free slot indices from an `alloc_counter` seed.
///
/// Slots outside `[0, 2^log_slots)` are masked via bitmask (no modulo bias
/// since we operate on power-of-two sizes).
/// The caller is responsible for checking actual slot occupancy.
pub fn generate_slot_hints(alloc_counter: u64, log_slots: u32, count: usize) -> Vec<u32> {
    debug_assert!(log_slots <= 32, "log_slots must fit in u32 slot index");
    let mask: u64 = (1u64 << log_slots) - 1;
    let mut state = alloc_counter;
    let mut hints = Vec::with_capacity(count);
    while hints.len() < count {
        let raw = splitmix64(&mut state);
        hints.push((raw & mask) as u32);
    }
    hints
}

/// Deduplicate slot hints and remove any slots already in `reserved`.
///
/// Preserves generation order. O(n log n).
pub fn deduplicate_hints(hints: Vec<u32>, reserved: &[u32]) -> Vec<u32> {
    let mut seen = std::collections::HashSet::new();
    for &r in reserved {
        seen.insert(r);
    }
    hints.into_iter().filter(|s| seen.insert(*s)).collect()
}

/// Compute the `alloc_counter` increment for a block that creates `n_outputs`
/// new outputs (including coinbase). The counter increments by 1 per mint.
pub fn alloc_counter_increment(n_outputs: u64) -> u64 {
    n_outputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_advances() {
        let mut s = 42u64;
        let a = splitmix64(&mut s);
        let b = splitmix64(&mut s);
        assert_ne!(a, b);
        assert_ne!(a, 42);
    }

    #[test]
    fn splitmix64_deterministic() {
        let mut s1 = 1234u64;
        let mut s2 = 1234u64;
        for _ in 0..100 {
            assert_eq!(splitmix64(&mut s1), splitmix64(&mut s2));
        }
    }

    #[test]
    fn splitmix64_bijective_on_small_sample() {
        // Check no collisions over 65536 consecutive inputs.
        let mut outputs = std::collections::HashSet::new();
        let mut s = 0u64;
        for _ in 0..65536 {
            let v = splitmix64(&mut s);
            assert!(outputs.insert(v), "collision detected");
        }
    }

    #[test]
    fn generate_correct_count() {
        let hints = generate_slot_hints(0, 24, 10);
        assert_eq!(hints.len(), 10);
    }

    #[test]
    fn slots_within_range() {
        let log_slots = 24;
        let cap = 1u64 << log_slots;
        let hints = generate_slot_hints(999, log_slots, 1000);
        for &h in &hints {
            assert!((h as u64) < cap, "slot {h} exceeds capacity {cap}");
        }
    }

    #[test]
    fn different_counters_different_hints() {
        let a = generate_slot_hints(0, 24, 5);
        let b = generate_slot_hints(1, 24, 5);
        assert_ne!(a, b);
    }

    #[test]
    fn deduplication_removes_reserved() {
        let hints = vec![1u32, 2, 3, 4, 5];
        let reserved = vec![2u32, 4];
        let result = deduplicate_hints(hints, &reserved);
        assert!(!result.contains(&2));
        assert!(!result.contains(&4));
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn deduplication_removes_duplicates_within_hints() {
        let hints = vec![1u32, 1, 2, 2, 3];
        let result = deduplicate_hints(hints, &[]);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn genesis_counter_starts_at_zero() {
        let hints_a = generate_slot_hints(0, 24, 3);
        let hints_b = generate_slot_hints(0, 24, 3);
        assert_eq!(hints_a, hints_b);
    }

    #[test]
    fn low_bits_uniformly_distributed() {
        // Verify that the bottom k bits of splitmix64 outputs are well-distributed.
        // With LCG, bottom bits have shorter period. With splitmix64 they should not.
        let mask = (1u64 << 24) - 1;
        let mut state = 0u64;
        let n = 100_000usize;
        let buckets = 256usize;
        let mut counts = vec![0usize; buckets];
        for _ in 0..n {
            let v = splitmix64(&mut state) & mask;
            counts[(v % buckets as u64) as usize] += 1;
        }
        let expected = n / buckets;
        for &c in &counts {
            // Allow ±20% deviation from uniform.
            assert!(
                c > expected * 80 / 100 && c < expected * 120 / 100,
                "bucket count {} deviates too far from expected {}",
                c,
                expected
            );
        }
    }
}
