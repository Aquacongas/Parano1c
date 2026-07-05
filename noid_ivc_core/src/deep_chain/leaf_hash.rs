//! Flat-basis replays of the wallet-capsule query-leaf hash schedules.
//!
//! Each FRI/source query opens a LEAF whose hash is a fixed chain of
//! `hash_pair`/`compress` over the queried symbols plus class-constant
//! metadata (domain tag, `log_rows`, `n_cols`, leaf index). The region layer
//! proves these chains with a deep-chain family (the item-3 clone of
//! `MerklePathFamily`); this module is the native flat-basis replay the
//! family and its gate are built against — the same single-basis convention
//! as [`super::source_tree`] (φ only at the symbol/digest boundary, every
//! interior lane a plain flat wire).

use crate::deep_chain::source_tree::{compress_iv_flat, flat_compress, flat_hash_pair, run_perm};
use crate::deep_chain::schedule::flat_of_tower_u128;
use crate::field::F128;
use noid_poseidon2b::native::permutation::STATE_SIZE;

/// Domain tag for encoded-source leaf hashes — the flat image of
/// `noid_fri_binius::interleaved_commit::SOURCE_LEAF_DOMAIN`. Kept in sync
/// with the native constant; a mismatch only yields honest-rejected proofs.
pub const SOURCE_LEAF_DOMAIN: u128 = 0xF21B_1D50_0000_0001u128;

/// Flat lane of a tower `u128` bit pattern (class-constant metadata and
/// queried symbols cross the region boundary through this linear map).
#[inline]
pub fn flat_lane(v: u128) -> F128 {
    flat_of_tower_u128(v)
}

/// Flat-basis replay of `source_leaf_hash(log_rows, n_cols, leaf_index,
/// symbols)`:
///
/// ```text
///   acc  = hash_pair(DOMAIN, log_rows)
///   meta = hash_pair(n_cols, leaf_index)
///   acc  = compress(acc, meta)
///   for k in 0..n_cols:  acc = compress(acc, hash_pair(sym[2k], sym[2k+1]))
/// ```
///
/// `symbols` are the `2·n_cols` queried codeword lanes already in the flat
/// basis. `log_rows`, `n_cols`, `leaf_index` are class/query metadata (their
/// flat images are formed here). Matches the native tower `source_leaf_hash`
/// under φ. Returns the leaf digest's two flat lanes.
pub fn flat_source_leaf_hash(
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[F128],
) -> [F128; 2] {
    assert_eq!(symbols.len(), n_cols * 2, "source leaf symbol count");
    let iv = compress_iv_flat();

    let acc = flat_hash_pair(flat_lane(SOURCE_LEAF_DOMAIN), flat_lane(log_rows as u128));
    let meta = flat_hash_pair(flat_lane(n_cols as u128), flat_lane(leaf_index as u128));
    let mut acc = flat_compress(iv, acc, meta);
    for k in 0..n_cols {
        let ph = flat_hash_pair(symbols[2 * k], symbols[2 * k + 1]);
        acc = flat_compress(iv, acc, ph);
    }
    acc
}

/// One source-leaf chain family instance. `n_cols` queried column pairs; the
/// per-leaf schedule occupies `4 + 3·n_cols` permutation slots (2 initial
/// `hash_pair`s + 1 two-slot `compress`, then per column a `hash_pair` + a
/// two-slot `compress`).
#[derive(Clone, Copy, Debug)]
pub struct SourceLeafChain {
    pub n_cols: usize,
}

impl SourceLeafChain {
    pub fn slots(&self) -> usize {
        4 + 3 * self.n_cols
    }
    pub fn stride(&self) -> usize {
        self.slots().next_power_of_two()
    }
    /// The slot holding the final accumulator (the leaf digest, `C0/C1`).
    pub fn digest_slot(&self) -> usize {
        3 + 3 * self.n_cols
    }
}

/// Flat-basis region columns of one source-leaf chain: every schedule slot's
/// permutation. `c[j][slot]` is the output state; the leaf digest is
/// `C0/C1` at [`SourceLeafChain::digest_slot`].
///
/// Slot roles (uniform distance-2 carry, matching the tree's `compress`
/// convention): `0` = `hash_pair(DOMAIN, log_rows)`, `1` =
/// `hash_pair(n_cols, leaf_index)`, `2/3` = the first `compress` (even
/// absorbs `acc0 = C(w−2)` on a fresh IV, odd feeds the even output forward
/// and absorbs `meta = C(w−2)`); then per column `k`: slot `4+3k` =
/// `hash_pair(sym[2k], sym[2k+1])`, `5+3k`/`6+3k` = the `compress` (even
/// absorbs the running `acc = C(w−2)`, odd absorbs `ph_k = C(w−2)`). Both
/// the acc-into-even and the hash-into-odd reads are exactly two slots back.
pub struct SourceLeafColumns {
    pub c: [Vec<F128>; STATE_SIZE],
    pub s0: [Vec<F128>; STATE_SIZE],
    pub s_out: [Vec<F128>; STATE_SIZE],
    pub digest: [F128; 2],
}

/// Replay one source-leaf chain in the flat basis and fill the region
/// columns. `symbols` are the `2·n_cols` queried flat lanes. The recomputed
/// digest matches [`flat_source_leaf_hash`] (hence native `source_leaf_hash`
/// under φ).
pub fn build_source_leaf_columns(
    chain: &SourceLeafChain,
    log_rows: usize,
    leaf_index: usize,
    symbols: &[F128],
    w_log: usize,
) -> SourceLeafColumns {
    let w = 1usize << w_log;
    assert!(w >= chain.slots(), "slot domain below the chain");
    assert_eq!(symbols.len(), chain.n_cols * 2, "source leaf symbol count");
    let iv = compress_iv_flat();

    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);

    let mut store = |slot: usize,
                     raw: [F128; STATE_SIZE],
                     c: &mut [Vec<F128>; STATE_SIZE]| {
        let (s0v, outv) = run_perm(raw);
        for j in 0..STATE_SIZE {
            s0[j][slot] = s0v[j];
            s_out[j][slot] = outv[j];
            c[j][slot] = outv[j];
        }
    };

    // Ghost default so the walk stays consistent on unused slots (raw = 0).
    for slot in 0..w {
        store(slot, [F128::ZERO; STATE_SIZE], &mut c);
    }

    // Initial block.
    store(
        0,
        [
            flat_lane(SOURCE_LEAF_DOMAIN),
            flat_lane(log_rows as u128),
            F128::ZERO,
            F128::ZERO,
        ],
        &mut c,
    );
    store(
        1,
        [
            flat_lane(chain.n_cols as u128),
            flat_lane(leaf_index as u128),
            F128::ZERO,
            F128::ZERO,
        ],
        &mut c,
    );
    // compress(acc0 = C(0), meta = C(1)).
    let acc0 = [c[0][0], c[1][0]];
    store(2, [acc0[0], acc0[1], iv[0], iv[1]], &mut c);
    let even_out: [F128; STATE_SIZE] = std::array::from_fn(|j| c[j][2]);
    let meta = [c[0][1], c[1][1]];
    store(
        3,
        [
            even_out[0] + meta[0],
            even_out[1] + meta[1],
            even_out[2],
            even_out[3],
        ],
        &mut c,
    );

    // Per-column steps.
    for k in 0..chain.n_cols {
        let hp = 4 + 3 * k;
        let ev = 5 + 3 * k;
        let od = 6 + 3 * k;
        store(
            hp,
            [symbols[2 * k], symbols[2 * k + 1], F128::ZERO, F128::ZERO],
            &mut c,
        );
        let acc = [c[0][ev - 2], c[1][ev - 2]]; // running acc, two slots back
        store(ev, [acc[0], acc[1], iv[0], iv[1]], &mut c);
        let even_out: [F128; STATE_SIZE] = std::array::from_fn(|j| c[j][ev]);
        let ph = [c[0][od - 2], c[1][od - 2]]; // ph_k = the hash_pair output, two slots back
        store(
            od,
            [
                even_out[0] + ph[0],
                even_out[1] + ph[1],
                even_out[2],
                even_out[3],
            ],
            &mut c,
        );
    }

    let d = chain.digest_slot();
    let digest = [c[0][d], c[1][d]];
    SourceLeafColumns {
        c,
        s0,
        s_out,
        digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The chain column replay's recomputed digest (from the distance-2
    /// carry slot layout) equals the direct `flat_source_leaf_hash` (hence
    /// native `source_leaf_hash` under φ) across shapes, and `c == s_out`
    /// (the digest columns are the walk outputs). This validates the slot
    /// layout the region DAG will wire.
    #[test]
    fn source_leaf_columns_digest_matches() {
        let mut seed = 0x5EEDu64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^= z >> 31;
            F128 {
                lo: z,
                hi: z.rotate_left(17),
            }
        };
        for (n_cols, log_rows, leaf_index) in [(1usize, 4usize, 0usize), (3, 6, 5), (4, 8, 37)] {
            let chain = SourceLeafChain { n_cols };
            let w_log = chain.stride().trailing_zeros() as usize;
            let symbols: Vec<F128> = (0..n_cols * 2).map(|_| next()).collect();
            let cols = build_source_leaf_columns(&chain, log_rows, leaf_index, &symbols, w_log);

            let direct = flat_source_leaf_hash(log_rows, n_cols, leaf_index, &symbols);
            assert_eq!(cols.digest, direct, "chain digest != flat_source_leaf_hash");
            for slot in 0..(1usize << w_log) {
                for j in 0..STATE_SIZE {
                    assert_eq!(cols.c[j][slot], cols.s_out[j][slot]);
                }
            }
        }
    }
}
